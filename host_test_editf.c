#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gui_render.h"
static unsigned fb[480*320];
static void fr(int x,int y,int w,int h,unsigned c){
  for(int j=y;j<y+h;j++)for(int i=x;i<x+w;i++) if(i>=0&&j>=0&&i<480&&j<320) fb[j*480+i]=c; }
static void tx(int x,int y,const char*s,unsigned c){ for(int k=0;s[k];k++) if(s[k]!=' ') fr(x+k*8+1,y+1,6,6,c); }
/* fake disk */
static char disk_buf[4096]; static int disk_len=-1; static char disk_name[64];
static int frd(const char*n,char*b,int cap){ if(disk_len<0||strcmp(n,disk_name)) return -1; memcpy(b,disk_buf,disk_len); return disk_len; }
static int fwr(const char*n,const char*b,int l){ strcpy(disk_name,n); memcpy(disk_buf,b,l); disk_len=l; return 0; }
static gui_file_ops_t FO={frd,fwr};
static gui_scene_t S;
#define CHECK(c) do{ if(!(c)){ printf("FAIL line %d: %s\n",__LINE__,#c); fails++; } }while(0)
static int fails=0;
static void click(int x,int y){ gui_scene_event(&S,x,y,1,1,1,0); gui_scene_event(&S,x,y,0,0,1,0); }
static void key(int k){ gui_scene_event(&S,0,0,0,0,1,k); }
static void type(const char*s){ while(*s) key(*s++); }
int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"rb"); fseek(f,0,SEEK_END); long n=ftell(f); rewind(f);
  unsigned char*img=malloc(n); fread(img,1,n,f);
  const void*blob; unsigned sz; int r=gui_elf_find_section(img,n,&blob,&sz);
  printf("find=%d nodes=%u\n",r,sz/(unsigned)sizeof(gui_node_t)); if(r) return 1;
  void*al=aligned_alloc(4,sz); memcpy(al,blob,sz);
  r=gui_scene_load(&S,al,sz); printf("load=%d\n",r); if(r) return 1;
  S.files=&FO;
  CHECK(!strcmp(S.tb[0],"untitled.txt"));
  CHECK(S.ta_focus==1);
  type("hello"); key('\n'); type("wor"); key('l'); key('d');
  CHECK(S.ta_len==11); CHECK(!memcmp(S.ta,"hello\nworld",11)); CHECK(S.ta_mod==1);
  key(-1); CHECK(S.ta_cur==5);                 /* up: col 5 of line 0 */
  key(-2); CHECK(S.ta_cur==11);                /* down back to end */
  key(-6); CHECK(S.ta_cur==6);                 /* home */
  key(-7); CHECK(S.ta_cur==11);                /* end */
  key(8); CHECK(S.ta_len==10);                 /* backspace */
  key(-6); key(-5); CHECK(S.ta_len==9); CHECK(!memcmp(S.ta,"hello\norl",9)); /* delete fwd */
  /* sticky column: line0 long, line1 short, line2 long */
  /* Save -> New -> Open round-trip */
  click(120,14);  CHECK(S.ta_mod==0); CHECK(disk_len==9); printf("msg after save: %s\n",S.msg);
  click(30,14);   CHECK(S.ta_len==0);
  click(80,14);   CHECK(S.ta_len==9); CHECK(!memcmp(S.ta,"hello\norl",9)); printf("msg after open: %s\n",S.msg);
  /* filename textbox gets keys, not the editor */
  click(100,36); CHECK(S.focus_tb==0 && S.ta_focus==0);
  int before=S.ta_len; key('x'); CHECK(S.ta_len==before); CHECK(!strcmp(S.tb[0],"untitled.txtx"));
  key(8);
  /* click into text area restores focus and places cursor */
  click(4+4+8*2, 52+2+10*1); CHECK(S.ta_focus==1 && S.focus_tb==-1); CHECK(S.ta_cur==6+2);
  /* scrolling: fill many lines */
  click(30,14); for(int i=0;i<40;i++){ type("line"); key('\n'); }
  CHECK(S.ta_sl>0); printf("scroll_line=%d\n",S.ta_sl);
  for(int i=0;i<300;i++) key('a'); CHECK(S.ta_sc>0); printf("scroll_col=%d\n",S.ta_sc);
  /* capacity */
  for(int i=0;i<5000;i++) key('z'); CHECK(S.ta_len==GUI_TA_CAP-1); printf("msg at cap: %s\n",S.msg);
  /* open missing file */
  click(100,36); for(int i=0;i<20;i++) key(8); type("nope"); click(80,14); CHECK(!strncmp(S.msg,"Open failed",11));
  /* empty name */
  click(100,36); for(int i=0;i<30;i++) key(8); CHECK(S.tb_len[0]==0); click(120,14); CHECK(!strncmp(S.msg,"Enter a filename",16));
  /* two-click quit with unsaved changes */
  click(100,100); CHECK(S.ta_focus==1); key('q'); CHECK(S.ta_mod==1);
  click(440,14); CHECK(S.quit==0 && S.quit_armed==1);
  click(440,14); CHECK(S.quit==1);
  /* unmodified quit = one click */
  static gui_scene_t T; gui_scene_load(&T,al,sz); memcpy(&S,&T,sizeof S); S.files=&FO;
  click(440,14); CHECK(S.quit==1);
  /* render */
  memcpy(&S,&T,sizeof S); S.files=&FO; type("render me"); gui_ops_t ops={fr,tx,8,8}; gui_scene_render(&S,&ops);
  FILE*o=fopen("editf_out.ppm","wb"); fprintf(o,"P6\n480 320\n255\n");
  for(int i=0;i<480*320;i++){fputc(fb[i]>>16,o);fputc(fb[i]>>8,o);fputc(fb[i],o);} fclose(o);
  /* hostile */
  static gui_scene_t B; CHECK(gui_scene_load(&B,aligned_alloc(4,88),88)<0);
  printf(fails?"\n%d FAILURES\n":"\nALL OK\n",fails); return fails?1:0; }
