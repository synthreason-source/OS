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

/* Optional file hooks for GUI_ACT_NEW/OPEN/SAVE.  The kernel plugs FAT32 in;
 * a NULL table (or NULL member) makes the action report "no file access".
 *   read : fill buf (<= cap bytes), return byte count or <0 on error
 *   write: store len bytes, return 0 on success                        */
typedef struct {
    int (*read )(const char *name, char *buf, int cap);
    int (*write)(const char *name, const char *buf, int len);
} gui_file_ops_t;

typedef struct {
    const gui_node_t *nodes; int count;
    int cw, ch; unsigned int bg;
    int vars[GUI_MAX_VARS];
    char tb[GUI_MAX_TEXTBOX][GUI_TEXTBOX_CAP]; int tb_len[GUI_MAX_TEXTBOX];
    int focus_tb, drag_node, hover, pressed, quit;
    /* text-area 0 (multi-line editor) */
    char ta[GUI_TA_CAP]; int ta_len, ta_cur, ta_pref, ta_sl, ta_sc;
    int ta_mod, ta_focus, quit_armed;
    char msg[40];
    const gui_file_ops_t *files;          /* set by the kernel, may be NULL */
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


/* ---- text-area editing helpers (flat buffer, '\n'-delimited lines) ---- */
#define GR_CW 8
#define GR_LH 10
static inline void gr_set_msg(gui_scene_t *s,const char *m){
    int i=0; while(m[i] && i<(int)sizeof s->msg-1){ s->msg[i]=m[i]; i++; } s->msg[i]=0; }
static inline int gr_ls(const gui_scene_t*s,int p){ while(p>0 && s->ta[p-1]!='\n') p--; return p; }
static inline int gr_le(const gui_scene_t*s,int p){ while(p<s->ta_len && s->ta[p]!='\n') p++; return p; }
static inline int gr_lineno(const gui_scene_t*s,int p){
    int l=0; for(int i=0;i<p && i<s->ta_len;i++) if(s->ta[i]=='\n') l++; return l; }
static inline int gr_pos(const gui_scene_t*s,int line,int col){
    int p=0,l=0; while(l<line && p<s->ta_len){ if(s->ta[p]=='\n') l++; p++; }
    int e=gr_le(s,p), q=p+col; if(q>e) q=e; return q; }
static inline void gr_setcur(gui_scene_t*s,int p){ s->ta_cur=p; s->ta_pref=p-gr_ls(s,p); }
static inline void gr_insert(gui_scene_t*s,char c){
    if(s->ta_len>=GUI_TA_CAP-1){ gr_set_msg(s,"Buffer full!"); return; }
    for(int i=s->ta_len;i>s->ta_cur;i--) s->ta[i]=s->ta[i-1];
    s->ta[s->ta_cur]=c; s->ta_len++; gr_setcur(s,s->ta_cur+1); s->ta_mod=1; }
static inline void gr_backspace(gui_scene_t*s){
    if(s->ta_cur<=0) return;
    for(int i=s->ta_cur-1;i<s->ta_len-1;i++) s->ta[i]=s->ta[i+1];
    s->ta_len--; gr_setcur(s,s->ta_cur-1); s->ta_mod=1; }
static inline void gr_delete(gui_scene_t*s){
    if(s->ta_cur>=s->ta_len) return;
    for(int i=s->ta_cur;i<s->ta_len-1;i++) s->ta[i]=s->ta[i+1];
    s->ta_len--; s->ta_mod=1; }
/* visible rows/cols of a text-area node (same math the renderer uses) */
static inline int gr_vis_cols(const gui_node_t*n){ int c=(n->w-8)/GR_CW; return c<1?1:c; }
static inline int gr_vis_rows(const gui_node_t*n){ int r=(n->h-4)/GR_LH; return r<1?1:r; }
static inline void gr_ta_scroll(gui_scene_t*s,const gui_node_t*n){
    int cl=gr_lineno(s,s->ta_cur), cc=s->ta_cur-gr_ls(s,s->ta_cur);
    int vr=gr_vis_rows(n), vc=gr_vis_cols(n);
    if(cl<s->ta_sl) s->ta_sl=cl;
    if(cl>=s->ta_sl+vr) s->ta_sl=cl-vr+1;
    if(cc<s->ta_sc) s->ta_sc=cc;
    if(cc>=s->ta_sc+vc) s->ta_sc=cc-vc+1;
    if(s->ta_sl<0) s->ta_sl=0;
    if(s->ta_sc<0) s->ta_sc=0; }
static inline const gui_node_t *gr_find_ta(const gui_scene_t*s){
    for(int i=1;i<s->count;i++) if(s->nodes[i].op==GUI_OP_TEXTAREA) return &s->nodes[i];
    return 0; }
static inline void gr_ta_key(gui_scene_t*s,int k){
    s->quit_armed=0;
    if      (k==-3) { if(s->ta_cur>0) gr_setcur(s,s->ta_cur-1); }               /* KEY_LEFT  */
    else if (k==-4) { if(s->ta_cur<s->ta_len) gr_setcur(s,s->ta_cur+1); }       /* KEY_RIGHT */
    else if (k==-1) { int l=gr_lineno(s,s->ta_cur); if(l>0) s->ta_cur=gr_pos(s,l-1,s->ta_pref); } /* UP   */
    else if (k==-2) { s->ta_cur=gr_pos(s,gr_lineno(s,s->ta_cur)+1,s->ta_pref); } /* DOWN      */
    else if (k==-6) { s->ta_cur=gr_ls(s,s->ta_cur); s->ta_pref=0; }              /* HOME      */
    else if (k==-7) { s->ta_cur=gr_le(s,s->ta_cur); s->ta_pref=s->ta_cur-gr_ls(s,s->ta_cur); } /* END */
    else if (k==-5) gr_delete(s);                                                /* DELETE    */
    else if (k==8 || k==127) gr_backspace(s);
    else if (k=='\n' || k=='\r') gr_insert(s,'\n');
    else if (k=='\t') { for(int i=0;i<4;i++) gr_insert(s,' '); }
    else if (k>=32 && k<127) gr_insert(s,(char)k); }

/* ---- file actions ---- */
static inline void gr_num(char *o,int *p,int v){ char t[12]; gr_itoa(v,t); for(int i=0;t[i];i++) o[(*p)++]=t[i]; o[*p]=0; }
static inline void gr_file_action(gui_scene_t*s,const gui_node_t*n){
    int slot=n->var; const char *name=s->tb[slot];
    if (n->aux==GUI_ACT_NEW){
        s->ta_len=0; s->ta_cur=0; s->ta_pref=0; s->ta_sl=0; s->ta_sc=0; s->ta_mod=0; s->quit_armed=0;
        gr_set_msg(s,"New file."); return; }
    if (!s->files){ gr_set_msg(s,"No file access."); return; }
    if (s->tb_len[slot]==0){ gr_set_msg(s,"Enter a filename first."); return; }
    if (n->aux==GUI_ACT_OPEN){
        if(!s->files->read){ gr_set_msg(s,"No file access."); return; }
        int rd=s->files->read(name,s->ta,GUI_TA_CAP-1);
        if (rd<0){ gr_set_msg(s,"Open failed."); return; }
        s->ta_len=rd; s->ta[rd]=0; s->ta_cur=0; s->ta_pref=0; s->ta_sl=0; s->ta_sc=0;
        s->ta_mod=0; s->quit_armed=0;
        char m[40]; int p=0; const char *a="Loaded "; while(*a) m[p++]=*a++;
        gr_num(m,&p,rd); const char *b=" bytes."; while(*b) m[p++]=*b++; m[p]=0; gr_set_msg(s,m);
    } else if (n->aux==GUI_ACT_SAVE){
        if(!s->files->write){ gr_set_msg(s,"No file access."); return; }
        if (s->files->write(name,s->ta,s->ta_len)==0){
            s->ta_mod=0; s->quit_armed=0;
            char m[40]; int p=0; const char *a="Saved "; while(*a) m[p++]=*a++;
            gr_num(m,&p,s->ta_len); const char *b=" bytes."; while(*b) m[p++]=*b++; m[p]=0; gr_set_msg(s,m);
        } else gr_set_msg(s,"Save failed.");
    } }

static inline int gui_scene_load(gui_scene_t *s, const void *blob, unsigned sz)
{
    unsigned i; unsigned char *z=(unsigned char*)s;
    for(i=0;i<sizeof *s;i++) z[i]=0;
    if (((unsigned long)blob & 3) || sz < sizeof(gui_node_t) || sz % sizeof(gui_node_t)) return -1;
    s->nodes=(const gui_node_t*)blob; s->count=(int)(sz/sizeof(gui_node_t));
    if (s->nodes[0].op!=GUI_OP_HEADER) return -2;
    s->cw=s->nodes[0].w; s->ch=s->nodes[0].h; s->bg=s->nodes[0].color;
    s->focus_tb=-1; s->drag_node=-1; s->hover=-1; s->pressed=-1;
    s->ta_focus=1; gr_set_msg(s,"Ready.");
    for(i=0;i<(unsigned)s->count;i++){            /* validate every node up front */
        const gui_node_t *n=&s->nodes[i];
        if (n->op>GUI_OP_STATUS) return -3;
        if ((n->op==GUI_OP_BUTTON||n->op==GUI_OP_SCROLL||n->op==GUI_OP_VALUE||
             n->op==GUI_OP_BARV||n->op==GUI_OP_INITVAR) && n->var>=GUI_MAX_VARS) return -4;
        if (n->op==GUI_OP_TEXTBOX && n->var>=GUI_MAX_TEXTBOX) return -4;
        if (n->op==GUI_OP_TEXTAREA && n->var>=GUI_MAX_TEXTAREA) return -4;
        if (n->op==GUI_OP_BUTTON && n->aux>=GUI_ACT_NEW && n->var>=GUI_MAX_TEXTBOX) return -4;
        if ((n->op==GUI_OP_SCROLL||n->op==GUI_OP_BARV) && n->b<=n->a) return -5;
        if (n->text[GUI_TEXT_LEN-1]!=0) return -6;
        if (n->op==GUI_OP_INITVAR) s->vars[n->var]=n->a;
        if (n->op==GUI_OP_TEXTBOX && n->text[0]) {       /* optional default text */
            int l=0; while(n->text[l] && l<GUI_TEXTBOX_CAP-1){ s->tb[n->var][l]=n->text[l]; l++; }
            s->tb[n->var][l]=0; s->tb_len[n->var]=l;
        }
    }
    return 0;
}

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
            const char *lb = (n->aux==GUI_ACT_QUIT_CONFIRM && s->quit_armed) ? "Sure?" : n->text;
            o->text(n->x+(n->w-gr_slen(lb)*o->glyph_w)/2, n->y+(n->h-o->glyph_h)/2, lb, GR_TEXT);
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
        case GUI_OP_TEXTAREA: {
            int vr=gr_vis_rows(n), vc=gr_vis_cols(n), line=0, col=0;
            o->fill_rect(n->x,n->y,n->w,n->h,0x14161Au);
            gr_stroke(o,n->x,n->y,n->w,n->h, s->ta_focus?GR_THUMB:GR_BORDER);
            for (int k=0;k<=s->ta_len;k++){
                int vis = line>=s->ta_sl && line<s->ta_sl+vr && col>=s->ta_sc && col<s->ta_sc+vc;
                int cx=n->x+4+(col-s->ta_sc)*GR_CW, cy=n->y+2+(line-s->ta_sl)*GR_LH;
                if (k==s->ta_cur && s->ta_focus && vis) o->fill_rect(cx,cy,1,8,GR_TEXT);
                if (k==s->ta_len) break;
                char c=s->ta[k];
                if (c=='\n'){ line++; col=0; continue; }
                if (vis){ char t[2]={c,0}; o->text(cx,cy,t,GR_TEXT); }
                col++;
                if (line>=s->ta_sl+vr) break;      /* nothing more is visible */
            }
        } break;
        case GUI_OP_STATUS: {
            char b[GUI_TEXTBOX_CAP+40]; int p=0; const char *a;
            a="Ln "; while(*a) b[p++]=*a++; gr_num(b,&p,gr_lineno(s,s->ta_cur)+1);
            a="  Col "; while(*a) b[p++]=*a++; gr_num(b,&p,s->ta_cur-gr_ls(s,s->ta_cur)+1);
            a="  "; while(*a) b[p++]=*a++; gr_num(b,&p,s->ta_len);
            b[p++]='/'; gr_num(b,&p,GUI_TA_CAP-1);
            if (s->ta_mod){ a=" *mod*"; while(*a) b[p++]=*a++; }
            b[p]=0; o->text(n->x,n->y,b,n->color);
            o->text(n->x,n->y+10,s->msg,n->color);
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
                else if (n->aux==GUI_ACT_QUIT_CONFIRM) {
                    if (!s->ta_mod || s->quit_armed) s->quit=1;
                    else { s->quit_armed=1; gr_set_msg(s,"Unsaved! Click again."); }
                }
                else if (n->aux>=GUI_ACT_NEW && n->aux<=GUI_ACT_SAVE) gr_file_action(s,n);
            }
        }
        if (left_clicked) {
            if (n->op==GUI_OP_SCROLL && gr_in(n,mx,my)) s->drag_node=i;
            if (n->op==GUI_OP_TEXTBOX) { if(gr_in(n,mx,my)) { s->focus_tb=n->var; s->ta_focus=0; }
                                         else if(s->focus_tb==n->var) s->focus_tb=-1; }
            if (n->op==GUI_OP_TEXTAREA && gr_in(n,mx,my)) {
                s->ta_focus=1; s->focus_tb=-1;
                int col=(mx-(n->x+4))/GR_CW+s->ta_sc, line=(my-(n->y+2))/GR_LH+s->ta_sl;
                if(col<0) col=0;
                if(line<0) line=0;
                gr_setcur(s,gr_pos(s,line,col)); s->quit_armed=0;
            }
        }
    }
    if (!left_down) { s->drag_node=-1; s->pressed=-1; }
    if (s->drag_node>=0) {
        const gui_node_t *n=&s->nodes[s->drag_node];
        int th=n->h-n->w; if(th<1)th=1;
        s->vars[n->var]=gr_clamp(n->a+(my-n->y)*(n->b-n->a)/th, n->a, n->b);
    }
    if (key && s->focus_tb<0 && s->ta_focus) gr_ta_key(s,key);
    { const gui_node_t *ta=gr_find_ta(s); if(ta) gr_ta_scroll(s,ta); }
    if (key && s->focus_tb>=0) {
        int t=s->focus_tb, *l=&s->tb_len[t];
        if ((key==8||key==127||key==-5) && *l>0) s->tb[t][--*l]=0;
        else if (key>=32 && key<127 && *l<GUI_TEXTBOX_CAP-1) { s->tb[t][(*l)++]=(char)key; s->tb[t][*l]=0; }
    }
    return s->quit;
}
#endif
