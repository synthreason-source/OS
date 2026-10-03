/* gui_scene.h -- static GUI scene format shared by guest ELFs (producer)
 * and the kernel (consumer).  A scene is a flat, pointer-free array of
 * fixed-size nodes stored in the ELF section ".guiscene".  No code runs
 * in the guest to draw it: the kernel finds the section, validates it,
 * and renders + hit-tests it itself.  Node 0 must be GUI_HEADER(). */
#ifndef GUI_SCENE_H
#define GUI_SCENE_H

#define GUI_SECTION_NAME ".guiscene"
#define GUI_MAGIC        0x31495547u      /* "GUI1" little-endian */
#define GUI_MAX_VARS     16
#define GUI_MAX_TEXTBOX  4
#define GUI_TEXTBOX_CAP  48
#define GUI_TEXT_LEN     20               /* incl. NUL */

enum {
    GUI_OP_HEADER = 0, GUI_OP_FILL, GUI_OP_STROKE, GUI_OP_TEXT, GUI_OP_BUTTON,
    GUI_OP_SCROLL, GUI_OP_TEXTBOX, GUI_OP_VALUE, GUI_OP_BARV, GUI_OP_INITVAR
};
enum { GUI_ACT_NONE = 0, GUI_ACT_ADD, GUI_ACT_QUIT };

typedef struct {                  /* 44 bytes, no pointers, no padding */
    unsigned char op, var, aux, flags;
    short x, y, w, h;
    unsigned int color;
    int a, b;
    char text[GUI_TEXT_LEN];
} gui_node_t;

#define GUI__N(op,var,aux,x,y,w,h,col,a,b,txt) \
    { (op),(var),(aux),0,(x),(y),(w),(h),(col),(a),(b),txt }

/* header: w,h = canvas size, color = background */
#define GUI_HEADER(w,h,bg)              GUI__N(GUI_OP_HEADER,0,0,0,0,w,h,bg,0,0,"")
#define GUI_FILL(x,y,w,h,c)             GUI__N(GUI_OP_FILL,0,0,x,y,w,h,c,0,0,"")
#define GUI_STROKE(x,y,w,h,c)           GUI__N(GUI_OP_STROKE,0,0,x,y,w,h,c,0,0,"")
#define GUI_TEXT(x,y,c,s)               GUI__N(GUI_OP_TEXT,0,0,x,y,0,0,c,0,0,s)
#define GUI_BUTTON(x,y,w,h,s,act,var,d) GUI__N(GUI_OP_BUTTON,var,act,x,y,w,h,0,d,0,s)
#define GUI_SCROLL(x,y,w,h,var,mn,mx)   GUI__N(GUI_OP_SCROLL,var,0,x,y,w,h,0,mn,mx,"")
#define GUI_TEXTBOX(x,y,w,h,slot)       GUI__N(GUI_OP_TEXTBOX,slot,0,x,y,w,h,0,0,0,"")
#define GUI_VALUE(x,y,c,var)            GUI__N(GUI_OP_VALUE,var,0,x,y,0,0,c,0,0,"")
#define GUI_BARV(x,y,w,h,c,var,mn,mx)   GUI__N(GUI_OP_BARV,var,0,x,y,w,h,c,mn,mx,"")
#define GUI_INITVAR(var,val)            GUI__N(GUI_OP_INITVAR,var,0,0,0,0,0,0,val,0,"")

/* Declare the scene.  `used` + `aligned` keep it through --gc-sections. */
#define GUI_SCENE(...) \
    const gui_node_t gui_scene_nodes[] \
        __attribute__((section(GUI_SECTION_NAME), used, aligned(4))) = { __VA_ARGS__ }

#endif
