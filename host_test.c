#include <stdio.h>
#include <stdlib.h>
#include "gui_render.h"
static unsigned fb[320*200];
static void fr(int x,int y,int w,int h,unsigned c){
  for(int j=y;j<y+h;j++)for(int i=x;i<x+w;i++) if(i>=0&&j>=0&&i<320&&j<200) fb[j*320+i]=c; }
/* placeholder text: 8x8 cell, block per non-space char (host test only) */
static void tx(int x,int y,const char*s,unsigned c){
  for(int k=0;s[k];k++) if(s[k]!=' ') fr(x+k*8+1,y+1,6,6,c); }
int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); long n=ftell(f); rewind(f);
  unsigned char*img=malloc(n); fread(img,1,n,f);
  const void*blob; unsigned sz; int r=gui_elf_find_section(img,n,&blob,&sz);
  printf("find_section=%d size=%u nodes=%u\n",r,sz,sz/(unsigned)sizeof(gui_node_t)); if(r) return 1;
  /* kernel would load into aligned memory; emulate that */
  void*al=aligned_alloc(4,sz); __builtin_memcpy(al,blob,sz);
  static gui_scene_t S; r=gui_scene_load(&S,al,sz); printf("load=%d\n",r); if(r) return 1;
  gui_ops_t ops={fr,tx,8,8};
  gui_scene_event(&S,20,20,1,1,1,0); gui_scene_event(&S,20,20,0,0,1,0);   /* click x1 */
  gui_scene_event(&S,20,20,1,1,1,0); gui_scene_event(&S,20,20,0,0,1,0);   /* click x2 */
  gui_scene_event(&S,20,20,1,1,1,0); gui_scene_event(&S,20,20,0,0,1,0);   /* click x3 */
  gui_scene_event(&S,286,40,1,1,1,0); gui_scene_event(&S,286,40,1,0,1,0); /* drag scroll */
  gui_scene_event(&S,286,40,0,0,1,0);
  gui_scene_event(&S,50,58,1,1,1,0); gui_scene_event(&S,50,58,0,0,1,0);   /* focus textbox */
  gui_scene_event(&S,50,58,0,0,1,'h'); gui_scene_event(&S,50,58,0,0,1,'i');
  printf("clicks=%d scroll=%d text='%s' quit=%d\n",S.vars[0],S.vars[1],S.tb[0],S.quit);
  gui_scene_render(&S,&ops);
  FILE*o=fopen("out.ppm","wb"); fprintf(o,"P6\n320 200\n255\n");
  for(int i=0;i<320*200;i++){fputc(fb[i]>>16,o);fputc(fb[i]>>8,o);fputc(fb[i],o);} fclose(o);
  gui_scene_event(&S,30,130,1,1,1,0); printf("after Quit click: quit=%d\n",S.quit);
  /* hostile inputs */
  unsigned char bad[44*2]={0}; static gui_scene_t B;
  printf("bad blob load=%d (expect <0)\n", gui_scene_load(&B,aligned_alloc(4,88),88));
  img[0]=0; printf("non-ELF find=%d (expect <0)\n",gui_elf_find_section(img,n,&blob,&sz));
  return 0; }
