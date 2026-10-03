/* gui_render.h -- kernel-side: locate .guiscene in an ELF32 image, validate
 * it, render it through caller-supplied primitives, and feed it input.
 * Freestanding: no libc, no allocation, no pointers read from the blob. */
#ifndef GUI_RENDER_H
#define GUI_RENDER_H
#include "gui_scene.h"

typedef struct {                       /* kernel plugs its own drawing in */
    void (*fill_rect)(int x,int y,int w,int h,unsigned int rgb);
    void (*text)(int x,int y,const char *s,unsigned int rgb);
    int  glyph_w, glyph_h;
} gui_ops_t;

typedef struct {
    const gui_node_t *nodes; int count;
    int cw, ch; unsigned int bg;
    int vars[GUI_MAX_VARS];
    char tb[GUI_MAX_TEXTBOX][GUI_TEXTBOX_CAP]; int tb_len[GUI_MAX_TEXTBOX];
    int focus_tb, drag_node, hover, pressed, quit;
} gui_scene_t;

/* ---- ELF32 section lookup (bounds-checked, byte-wise, LE) ---- */
static inline unsigned gr_u16(const unsigned char*p){return p[0]|(p[1]<<8);}
static inline unsigned gr_u32(const unsigned char*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned)p[3]<<24);}
static inline int gr_streq(const unsigned char*a,unsigned al,const char*b){
    unsigned i=0; for(;;i++){ if(i>=al) return 0; if(a[i]!=(unsigned char)b[i]) return 0; if(!b[i]) return 1; } }

static inline int gui_elf_find_section(const void *img, unsigned len,
                                const void **out, unsigned *outsz)
{
    const unsigned char *e = (const unsigned char*)img;
    if (len < 52 || e[0]!=0x7f || e[1]!='E' || e[2]!='L' || e[3]!='F') return -1;
    if (e[4]!=1 || e[5]!=1) return -2;                 /* ELF32, little-endian */
    unsigned shoff=gr_u32(e+0x20), shes=gr_u16(e+0x2E), shn=gr_u16(e+0x30), shstr=gr_u16(e+0x32);
    if (shes<40 || shn==0 || shstr>=shn) return -3;
    if (shoff>len || (unsigned)shn*shes > len-shoff) return -3;
    const unsigned char *sh = e+shoff, *strh = sh+shstr*shes;
    unsigned stro=gr_u32(strh+16), strs=gr_u32(strh+20);
    if (stro>len || strs>len-stro) return -3;
    for (unsigned i=0;i<shn;i++){
        const unsigned char *s = sh+i*shes;
        unsigned nm=gr_u32(s), off=gr_u32(s+16), sz=gr_u32(s+20);
        if (nm>=strs) continue;
        if (gr_streq(e+stro+nm, strs-nm, GUI_SECTION_NAME)) {
            if (off>len || sz>len-off) return -4;
            *out = e+off; *outsz = sz; return 0;
        }
    }
    return -5;                                          /* section absent */
}

static inline int gui_scene_load(gui_scene_t *s, const void *blob, unsigned sz)
{
    unsigned i; unsigned char *z=(unsigned char*)s;
    for(i=0;i<sizeof *s;i++) z[i]=0;
    if (((unsigned long)blob & 3) || sz < sizeof(gui_node_t) || sz % sizeof(gui_node_t)) return -1;
    s->nodes=(const gui_node_t*)blob; s->count=(int)(sz/sizeof(gui_node_t));
    if (s->nodes[0].op!=GUI_OP_HEADER) return -2;
    s->cw=s->nodes[0].w; s->ch=s->nodes[0].h; s->bg=s->nodes[0].color;
    s->focus_tb=-1; s->drag_node=-1; s->hover=-1; s->pressed=-1;
    for(i=0;i<(unsigned)s->count;i++){            /* validate every node up front */
        const gui_node_t *n=&s->nodes[i];
        if (n->op>GUI_OP_INITVAR) return -3;
        if ((n->op==GUI_OP_BUTTON||n->op==GUI_OP_SCROLL||n->op==GUI_OP_VALUE||
             n->op==GUI_OP_BARV||n->op==GUI_OP_INITVAR) && n->var>=GUI_MAX_VARS) return -4;
        if (n->op==GUI_OP_TEXTBOX && n->var>=GUI_MAX_TEXTBOX) return -4;
        if ((n->op==GUI_OP_SCROLL||n->op==GUI_OP_BARV) && n->b<=n->a) return -5;
        if (n->text[GUI_TEXT_LEN-1]!=0) return -6;
        if (n->op==GUI_OP_INITVAR) s->vars[n->var]=n->a;
    }
    return 0;
}

static inline int gr_in(const gui_node_t*n,int x,int y){
    return x>=n->x && y>=n->y && x<n->x+n->w && y<n->y+n->h; }
static inline int gr_clamp(int v,int lo,int hi){return v<lo?lo:(v>hi?hi:v);}
static inline int gr_slen(const char*s){int n=0;while(s[n])n++;return n;}
static inline void gr_itoa(int v,char*o){
    char t[12]; int n=0,k=0; unsigned u=v<0?(unsigned)-v:(unsigned)v;
    if(v<0){ o[k++]='-'; }
    if(!u){ t[n++]='0'; }
    while(u){ t[n++]=(char)('0'+u%10); u/=10; }
    while(n){ o[k++]=t[--n]; }
    o[k]=0; }
static inline void gr_stroke(const gui_ops_t*o,int x,int y,int w,int h,unsigned c){
    o->fill_rect(x,y,w,1,c); o->fill_rect(x,y+h-1,w,1,c);
    o->fill_rect(x,y,1,h,c); o->fill_rect(x+w-1,y,1,h,c); }

#define GR_BTN 0x3A3A3Au
#define GR_BTN_HOT 0x505050u
#define GR_BTN_DOWN 0x202020u
#define GR_BORDER 0x909090u
#define GR_TEXT 0xE0E0E0u
#define GR_THUMB 0x4FA3FFu
#define GR_TRACK 0x181818u

static inline void gui_scene_render(const gui_scene_t *s, const gui_ops_t *o)
{
    o->fill_rect(0,0,s->cw,s->ch,s->bg);
    for (int i=1;i<s->count;i++){
        const gui_node_t *n=&s->nodes[i]; char buf[16];
        switch(n->op){
        case GUI_OP_FILL:   o->fill_rect(n->x,n->y,n->w,n->h,n->color); break;
        case GUI_OP_STROKE: gr_stroke(o,n->x,n->y,n->w,n->h,n->color); break;
        case GUI_OP_TEXT:   o->text(n->x,n->y,n->text,n->color); break;
        case GUI_OP_VALUE:  gr_itoa(s->vars[n->var],buf); o->text(n->x,n->y,buf,n->color); break;
        case GUI_OP_BUTTON: {
            unsigned c = s->pressed==i?GR_BTN_DOWN : s->hover==i?GR_BTN_HOT : GR_BTN;
            o->fill_rect(n->x,n->y,n->w,n->h,c); gr_stroke(o,n->x,n->y,n->w,n->h,GR_BORDER);
            o->text(n->x+(n->w-gr_slen(n->text)*o->glyph_w)/2, n->y+(n->h-o->glyph_h)/2, n->text, GR_TEXT);
        } break;
        case GUI_OP_SCROLL: {
            int span=n->b-n->a, th=n->h-n->w; if(th<1)th=1;
            int ty=n->y+(s->vars[n->var]-n->a)*th/span;
            o->fill_rect(n->x,n->y,n->w,n->h,GR_TRACK); gr_stroke(o,n->x,n->y,n->w,n->h,GR_BORDER);
            o->fill_rect(n->x+1,ty,n->w-2,n->w,GR_THUMB);
        } break;
        case GUI_OP_BARV: {
            int span=n->b-n->a, v=gr_clamp(s->vars[n->var],n->a,n->b);
            int bh=2+(n->h-2)*(v-n->a)/span;
            o->fill_rect(n->x,n->y+n->h-bh,n->w,bh,n->color);
            gr_stroke(o,n->x,n->y,n->w,n->h,GR_BORDER);
        } break;
        case GUI_OP_TEXTBOX: {
            o->fill_rect(n->x,n->y,n->w,n->h,0x101010u);
            gr_stroke(o,n->x,n->y,n->w,n->h, s->focus_tb==n->var?GR_THUMB:GR_BORDER);
            o->text(n->x+3,n->y+(n->h-o->glyph_h)/2,s->tb[n->var],GR_TEXT);
            if(s->focus_tb==n->var)
                o->fill_rect(n->x+3+s->tb_len[n->var]*o->glyph_w,n->y+2,1,n->h-4,GR_TEXT);
        } break;
        default: break;
        }
    }
}

/* Feed one input snapshot (matches the mouse_poll()/key_poll() ABI).
 * mx,my are canvas-local. Returns 1 once a QUIT button has fired. */
static inline int gui_scene_event(gui_scene_t *s, int mx,int my,
                           int left_down,int left_clicked,int in_window,int key)
{
    s->hover=-1;
    if (!in_window) { s->pressed=-1; if(!left_down) s->drag_node=-1; }
    for (int i=1;i<s->count && in_window;i++){
        const gui_node_t *n=&s->nodes[i];
        if (n->op==GUI_OP_BUTTON && gr_in(n,mx,my)) {
            s->hover=i; if(left_down) s->pressed=i;
            if (left_clicked) {
                if (n->aux==GUI_ACT_ADD) s->vars[n->var]+=n->a;
                else if (n->aux==GUI_ACT_QUIT) s->quit=1;
            }
        }
        if (left_clicked) {
            if (n->op==GUI_OP_SCROLL && gr_in(n,mx,my)) s->drag_node=i;
            if (n->op==GUI_OP_TEXTBOX) { if(gr_in(n,mx,my)) s->focus_tb=n->var;
                                         else if(s->focus_tb==n->var) s->focus_tb=-1; }
        }
    }
    if (!left_down) { s->drag_node=-1; s->pressed=-1; }
    if (s->drag_node>=0) {
        const gui_node_t *n=&s->nodes[s->drag_node];
        int th=n->h-n->w; if(th<1)th=1;
        s->vars[n->var]=gr_clamp(n->a+(my-n->y)*(n->b-n->a)/th, n->a, n->b);
    }
    if (key && s->focus_tb>=0) {
        int t=s->focus_tb, *l=&s->tb_len[t];
        if ((key==8||key==127||key==-5) && *l>0) s->tb[t][--*l]=0;
        else if (key>=32 && key<127 && *l<GUI_TEXTBOX_CAP-1) { s->tb[t][(*l)++]=(char)key; s->tb[t][*l]=0; }
    }
    return s->quit;
}
#endif
