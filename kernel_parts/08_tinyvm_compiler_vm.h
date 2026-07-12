#pragma once
// 08_tinyvm_compiler_vm.h
// The TinyVM toy language: lexer/tokenizer, compiler, bytecode VM,
// and the .obj object-file format used by 'compile'/'run'.
// Extracted from kernel.cpp (original lines 5409-6668) as part of
// splitting the monolithic kernel into per-component files. Order matters:
// this file relies on declarations from the kernel_parts files included
// before it in kernel.cpp, and is itself included there in sequence --
// it is NOT a standalone/independently-compilable translation unit.


// ============================================================
// Enhanced Bytecode ISA with Hardware Discovery and MMIO
// ============================================================
enum TOp : unsigned char {
    // stack/data
    T_NOP=0, T_PUSH_IMM, T_PUSH_STR, T_LOAD_LOCAL, T_STORE_LOCAL, T_POP,

    // arithmetic / unary
    T_ADD, T_SUB, T_MUL, T_DIV, T_NEG,

    // comparisons
    T_EQ, T_NE, T_LT, T_LE, T_GT, T_GE,

    // control flow
    T_JMP, T_JZ, T_JNZ, T_RET,

    // I/O and args
    T_PRINT_INT, T_PRINT_CHAR, T_PRINT_STR, T_PRINT_ENDL, T_PRINT_INT_ARRAY, T_PRINT_STRING_ARRAY,
    T_READ_INT, T_READ_CHAR, T_READ_STR,
    T_PUSH_ARGC, T_PUSH_ARGV_PTR,

    // File I/O operations
    T_READ_FILE, T_WRITE_FILE, T_APPEND_FILE,

    // Array operations
    T_ALLOC_ARRAY, T_LOAD_ARRAY, T_STORE_ARRAY, T_ARRAY_SIZE, T_ARRAY_RESIZE,

    // String operations
    T_STR_CONCAT, T_STR_LENGTH, T_STR_SUBSTR, T_INT_TO_STR, T_STR_COMPARE,
    T_STR_FIND_CHAR, T_STR_FIND_STR, T_STR_FIND_LAST_CHAR, T_STR_CONTAINS,
    T_STR_STARTS_WITH, T_STR_ENDS_WITH, T_STR_COUNT_CHAR, T_STR_REPLACE_CHAR,

    // NEW: Hardware Discovery and Memory-Mapped I/O
    T_SCAN_HARDWARE,      // () -> device_count
    T_GET_DEVICE_INFO,    // (device_index) -> device_array_handle
    T_MMIO_READ8,         // (address) -> uint8_value
    T_MMIO_READ16,        // (address) -> uint16_value
    T_MMIO_READ32,        // (address) -> uint32_value
    T_MMIO_READ64,        // (address) -> uint64_value (split into two 32-bit values)
    T_MMIO_WRITE8,        // (address, value) -> success
    T_MMIO_WRITE16,       // (address, value) -> success
    T_MMIO_WRITE32,       // (address, value) -> success
    T_MMIO_WRITE64,       // (address, low32, high32) -> success
    T_GET_HARDWARE_ARRAY, // () -> hardware_device_array_handle
    T_DISPLAY_MEMORY_MAP // () -> displays formatted memory map
};

// ============================================================
// Enhanced Program buffers with hardware support
// ============================================================
struct TProgram {
    static const int CODE_MAX = 8192;
    unsigned char code[CODE_MAX];
    int pc = 0;

    static const int LIT_MAX = 4096;
    char lit[LIT_MAX];
    int lit_top = 0;

    static const int LOC_MAX = 32;
    char  loc_name[LOC_MAX][32];
    unsigned char loc_type[LOC_MAX]; // 0=int,1=char,2=string,3=int_array,4=string_array,5=device_array
    int   loc_array_size[LOC_MAX];
    int   loc_count = 0;

    int add_local(const char* name, unsigned char t, int array_size = 0){
        for(int i=0;i<loc_count;i++){ if(simple_strcmp(loc_name[i], name)==0) return i; }
        if(loc_count>=LOC_MAX) return -1;
        simple_strcpy(loc_name[loc_count], name);
        loc_type[loc_count]=t;
        loc_array_size[loc_count] = array_size;
        return loc_count++;
    }
    int get_local(const char* name){
        for(int i=0;i<loc_count;i++){ if(simple_strcmp(loc_name[i], name)==0) return i; }
        return -1;
    }
    int get_local_type(int idx){ return (idx>=0 && idx<loc_count)? loc_type[idx] : 0; }
    int get_array_size(int idx){ return (idx>=0 && idx<loc_count)? loc_array_size[idx] : 0; }

    void emit1(unsigned char op){ if(pc<CODE_MAX) code[pc++]=op; }
    void emit4(int v){ if(pc+4<=CODE_MAX){ code[pc++]=v&0xff; code[pc++]=(v>>8)&0xff; code[pc++]=(v>>16)&0xff; code[pc++]=(v>>24)&0xff; } }
    int  mark(){ return pc; }
    void patch4(int at, int v){ if(at+4<=CODE_MAX){ code[at+0]=v&0xff; code[at+1]=(v>>8)&0xff; code[at+2]=(v>>16)&0xff; code[at+3]=(v>>24)&0xff; } }

    const char* add_lit(const char* s){
        int n = tcc_strlen(s)+1;
        if(lit_top+n > LIT_MAX) return "";
        char* p = &lit[lit_top];
        simple_memcpy(p, s, n);
        lit_top += n;
        return p;
    }
};

// ============================================================
// Enhanced Tokenizer with hardware and MMIO keywords
// ============================================================
enum TTokType { TT_EOF, TT_ID, TT_NUM, TT_STR, TT_CH, TT_KW, TT_OP, TT_PUNC };
struct TTok { TTokType t; char v[256]; int ival; };

struct TLex {
    const char* src; int pos; int line;
    void init(const char* s){ src=s; pos=0; line=1; }

    void skipws(){
        for(;;){
            char c=src[pos];
            if(c==' '||c=='\t'||c=='\r'||c=='\n'){ if(c=='\n') line++; pos++; continue; }
            if(c=='/' && src[pos+1]=='/'){ pos+=2; while(src[pos] && src[pos]!='\n') pos++; continue; }
            if(c=='/' && src[pos+1]=='*'){ pos+=2; while(src[pos] && !(src[pos]=='*'&&src[pos+1]=='/')) pos++; if(src[pos]) pos+=2; continue; }
            break;
        }
    }

    TTok number(){
        TTok t; t.t=TT_NUM; t.ival=0; int i=0;
        // Support hex numbers (0x prefix)
        if(src[pos] == '0' && (src[pos+1] == 'x' || src[pos+1] == 'X')) {
            pos += 2;
            t.v[i++] = '0'; t.v[i++] = 'x';
            while(i < 63 && ((src[pos] >= '0' && src[pos] <= '9') ||
                             (src[pos] >= 'a' && src[pos] <= 'f') ||
                             (src[pos] >= 'A' && src[pos] <= 'F'))) {
                char c = src[pos];
                t.v[i++] = c;
                if(c >= '0' && c <= '9') t.ival = t.ival * 16 + (c - '0');
                else if(c >= 'a' && c <= 'f') t.ival = t.ival * 16 + (c - 'a' + 10);
                else if(c >= 'A' && c <= 'F') t.ival = t.ival * 16 + (c - 'A' + 10);
                pos++;
            }
        } else {
            while(tcc_is_digit(src[pos])){ t.v[i++]=src[pos]; t.ival = t.ival*10 + (src[pos]-'0'); pos++; if(i>=63) break; }
        }
        t.v[i]=0; return t;
    }

    TTok ident(){
        TTok t; t.t=TT_ID; int i=0;
        while(tcc_is_alnum(src[pos])){ t.v[i++]=src[pos++]; if(i>=63) break; } t.v[i]=0;
        // Enhanced keywords with hardware and MMIO functions
        const char* kw[]={"int","char","string","return","if","else","while","break","continue",
                          "cin","cout","endl","argc","argv","read_file","write_file","append_file",
                          "array_size","array_resize","str_length","str_substr","int_to_str","str_compare",
                          "str_find_char","str_find_str","str_find_last_char","str_contains",
                          "str_starts_with","str_ends_with","str_count_char","str_replace_char",
                          "scan_hardware","get_device_info","get_hardware_array","display_memory_map",
                          "mmio_read8","mmio_read16","mmio_read32","mmio_read64",
                          "mmio_write8","mmio_write16","mmio_write32","mmio_write64",0};
        for(int k=0; kw[k]; ++k){ if(simple_strcmp(t.v,kw[k])==0){ t.t=TT_KW; break; } }
        return t;
    }

    TTok string(){
        TTok t; t.t=TT_STR; int i=0; pos++;
        while(src[pos] && src[pos]!='"'){ if(i<256) t.v[i++]=src[pos]; pos++; }
        t.v[i]=0; if(src[pos]=='"') pos++; return t;
    }

    TTok chlit(){
        TTok t; t.t=TT_CH; t.v[0]=0; int v=0; pos++; // skip '
        if(src[pos] && src[pos+1]=='\''){ v = (unsigned char)src[pos]; pos+=2; }
        t.ival = v; return t;
    }

    TTok op_or_punc(){
        TTok t; t.t=TT_OP; t.v[0]=src[pos]; t.v[1]=0; char c=src[pos];
        if(c=='<' && src[pos+1]=='<'){ t.v[0]='<'; t.v[1]='<'; t.v[2]=0; pos+=2; return t; }
        if(c=='>' && src[pos+1]=='>'){ t.v[0]='>'; t.v[1]='>'; t.v[2]=0; pos+=2; return t; }
        if((c=='='||c=='!'||c=='<'||c=='>') && src[pos+1]=='='){ t.v[0]=c; t.v[1]='='; t.v[2]=0; pos+=2; return t; }
        pos++; if(c=='('||c==')'||c=='{'||c=='}'||c==';'||c==','||c=='['||c==']') t.t=TT_PUNC; return t;
    }

    TTok next(){
        skipws();
        if(src[pos]==0){ TTok t; t.t=TT_EOF; t.v[0]=0; return t; }
        if(src[pos]=='"') return string();
        if(src[pos]=='\'') return chlit();
        if(tcc_is_digit(src[pos]) || (src[pos]=='0' && (src[pos+1]=='x'||src[pos+1]=='X'))) return number();
        if(tcc_is_alpha(src[pos])) return ident();
        return op_or_punc();
    }
};

// ============================================================
// Enhanced Parser / Compiler with Hardware and MMIO support
// ============================================================
struct TCompiler {
    TLex lx; TTok tk; TProgram pr;

    int brk_pos[32]; int brk_cnt=0;
    int cont_pos[32]; int cont_cnt=0;

    void adv(){ tk = lx.next(); }
    int  accept(const char* s){ if(simple_strcmp(tk.v,s)==0){ adv(); return 1; } return 0; }
    void expect(const char* s){ if(!accept(s)) { printf("Parse error near: %s\n", tk.v); } }

    void parse_primary(){
        if(tk.t==TT_NUM){ pr.emit1(T_PUSH_IMM); pr.emit4(tk.ival); adv(); return; }
        if(tk.t==TT_CH){ pr.emit1(T_PUSH_IMM); pr.emit4(tk.ival); adv(); return; }
        if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"argc")==0){ pr.emit1(T_PUSH_ARGC); adv(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); return; }

        // File I/O built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"read_file")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_READ_FILE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"write_file")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_WRITE_FILE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"append_file")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_APPEND_FILE); return;
        }

        // Array built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"array_size")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_ARRAY_SIZE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"array_resize")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_ARRAY_RESIZE); return;
        }

        // String built-ins
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_length")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_STR_LENGTH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_substr")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_STR_SUBSTR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"int_to_str")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_INT_TO_STR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_compare")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_COMPARE); return;
        }

        // String search functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_str")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_STR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_find_last_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_FIND_LAST_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_contains")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_CONTAINS); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_starts_with")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_STARTS_WITH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_ends_with")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_ENDS_WITH); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_count_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_STR_COUNT_CHAR); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"str_replace_char")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_STR_REPLACE_CHAR); return;
        }

        // NEW: Hardware Discovery Functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"scan_hardware")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_SCAN_HARDWARE); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"get_device_info")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_GET_DEVICE_INFO); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"get_hardware_array")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_GET_HARDWARE_ARRAY); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"display_memory_map")==0){
            adv(); expect("("); expect(")"); pr.emit1(T_DISPLAY_MEMORY_MAP); return;
        }

        // NEW: Memory-Mapped I/O Functions
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read8")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ8); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read16")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ16); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read32")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ32); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_read64")==0){
            adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_MMIO_READ64); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write8")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE8); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write16")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE16); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write32")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE32); return;
        }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"mmio_write64")==0){
            adv(); expect("("); parse_expression(); expect(","); parse_expression(); expect(",");
            parse_expression(); expect(")"); pr.emit1(T_MMIO_WRITE64); return;
        }

        if(tk.t==TT_PUNC && tk.v[0]=='('){ adv(); parse_expression(); expect(")"); return; }

        if(tk.t==TT_ID){
            int idx = pr.get_local(tk.v);
            if(idx<0){ printf("Unknown var %s\n", tk.v); }
            char var_name[32]; simple_strcpy(var_name, tk.v);
            adv();

            // Array indexing
            if(tk.t==TT_PUNC && tk.v[0]=='['){
                pr.emit1(T_LOAD_LOCAL); pr.emit4(idx); // push handle
                adv(); // past '['
                parse_expression(); // push index
                expect("]");
                pr.emit1(T_LOAD_ARRAY);
                return;
            }

            pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);
            return;
        }
    }

    void parse_unary(){
        if(accept("-")){ parse_unary(); pr.emit1(T_NEG); return; }
        parse_primary();
    }

    void parse_term(){
        parse_unary();
        while(tk.v[0]=='*' || tk.v[0]=='/'){
            char op=tk.v[0]; adv(); parse_unary();
            pr.emit1(op=='*'?T_MUL:T_DIV);
        }
    }

    void parse_arith(){
        parse_term();
        while(tk.v[0]=='+' || tk.v[0]=='-'){
            char op=tk.v[0]; adv(); parse_term();
            if(op=='+') {
                pr.emit1(T_ADD); // This will be overridden for strings in VM
            } else {
                pr.emit1(T_SUB);
            }
        }
    }

    void parse_cmp(){
        parse_arith();
        while(tk.t==TT_OP && (simple_strcmp(tk.v,"==")==0 || simple_strcmp(tk.v,"!=")==0 ||
              simple_strcmp(tk.v,"<")==0 || simple_strcmp(tk.v,"<=")==0 ||
              simple_strcmp(tk.v,">")==0 || simple_strcmp(tk.v,">=")==0)){
            char opv[3]; simple_strcpy(opv, tk.v); adv(); parse_arith();
            if(simple_strcmp(opv,"==")==0) pr.emit1(T_EQ);
            else if(simple_strcmp(opv,"!=")==0) pr.emit1(T_NE);
            else if(simple_strcmp(opv,"<")==0)  pr.emit1(T_LT);
            else if(simple_strcmp(opv,"<=")==0) pr.emit1(T_LE);
            else if(simple_strcmp(opv,">")==0)  pr.emit1(T_GT);
            else pr.emit1(T_GE);
        }
    }

    void parse_expression(){ parse_cmp(); }

    void parse_decl(unsigned char tkind){
        adv(); // past type keyword
        if(tk.t!=TT_ID){ printf("Expected identifier\n"); return; }
        char nm[32]; simple_strcpy(nm, tk.v); adv();

        int array_size = 0;
        // Array declaration syntax: int arr[size] or string arr[size]
        if(tk.t==TT_PUNC && tk.v[0]=='['){
            adv();
            if(tk.t==TT_NUM){
                array_size = tk.ival;
                adv();
            } else {
                printf("Expected array size\n"); return;
            }
            expect("]");

            if (tkind == 0) tkind = 3; // int -> int_array
            else if (tkind == 2) tkind = 4; // string -> string_array
        }

        int idx = pr.add_local(nm, tkind, array_size);

        // If it's an array, allocate it now, before parsing initializer
        if (tkind == 3 || tkind == 4) {
            pr.emit1(T_PUSH_IMM); pr.emit4(array_size);
            pr.emit1(T_ALLOC_ARRAY);
            pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
        }

        if(accept("=")){
            if(tkind==3 || tkind==4){ // Array initialization
                expect("{");
                int i = 0;
                do {
                    if (tk.t == TT_PUNC && tk.v[0] == '}') break; // empty list or trailing comma
                    if (i >= array_size) {
                        printf("Too many initializers for array\n");
                        while(!accept("}")) { if(tk.t==TT_EOF) break; adv(); }
                        goto end_init;
                    }

                    pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);      // 1. Push handle
                    pr.emit1(T_PUSH_IMM); pr.emit4(i);        // 2. Push index
                    parse_expression();                       // 3. Push value
                    pr.emit1(T_STORE_ARRAY);                    // 4. Store
                    i++;
                } while(accept(","));
                expect("}");
                end_init:;
            } else if(tkind==2){ // string
                if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); }
                else if(tk.t==TT_ID){ int j=pr.get_local(tk.v); adv(); pr.emit1(T_LOAD_LOCAL); pr.emit4(j); }
                else { parse_expression(); }
                pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            } else {
                parse_expression();
                pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            }
        }
        expect(";");
    }

    void parse_assign_or_coutcin(){
        if(tk.t==TT_KW && simple_strcmp(tk.v,"cout")==0){ adv();
            for(;;){
                expect("<<");
                if(tk.t==TT_KW && simple_strcmp(tk.v,"endl")==0){ adv(); pr.emit1(T_PRINT_ENDL); }
                else if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); pr.emit1(T_PRINT_STR); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); pr.emit1(T_PRINT_STR); }
                else if(tk.t==TT_ID){
                    char var_name[32]; simple_strcpy(var_name, tk.v);
                    int idx = pr.get_local(tk.v); int ty = pr.get_local_type(idx); adv();

                    // Handle array element printing vs whole array printing
                    if(tk.t==TT_PUNC && tk.v[0]=='['){
                        pr.emit1(T_LOAD_LOCAL); pr.emit4(idx); // load array
                        adv(); // past '['
                        parse_expression(); // push index
                        expect("]");
                        pr.emit1(T_LOAD_ARRAY); // load element
                        if (ty == 3) pr.emit1(T_PRINT_INT);      // int array element
                        else if (ty == 4) pr.emit1(T_PRINT_STR);  // string array element
                        else if (ty == 5) pr.emit1(T_PRINT_INT);  // device array element
                    } else {
                        pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);
                        if(ty==4) pr.emit1(T_PRINT_STRING_ARRAY); // Print whole string array
                        else if(ty==3) pr.emit1(T_PRINT_INT_ARRAY); // Print whole int array
                        else if(ty==2) pr.emit1(T_PRINT_STR);
                        else if(ty==1) pr.emit1(T_PRINT_CHAR);
                        else pr.emit1(T_PRINT_INT);
                    }
                } else { parse_expression(); pr.emit1(T_PRINT_INT); }
                if(tk.t==TT_PUNC && tk.v[0]==';'){ adv(); break; }
            }
            return;
        }
        if (tk.t==TT_KW && simple_strcmp(tk.v,"cin")==0) {
			adv();
			for (;;) {
				expect(">>");
				if (tk.t != TT_ID) {
					printf("cin expects identifier\n");
					return;
				}
				int idx = pr.get_local(tk.v);
				int ty  = pr.get_local_type(idx);
				adv(); // past identifier

				// CRITICAL FIX: Emit the variable index with the READ instruction
				// so the VM knows WHERE to store the result
				if (ty == 2) {
					pr.emit1(T_READ_STR);
					pr.emit4(idx);  // Index to store into
				}
				else if (ty == 1) {
					pr.emit1(T_READ_CHAR);
					pr.emit4(idx);
				}
				else {
					pr.emit1(T_READ_INT);
					pr.emit4(idx);
				}

				// DO NOT emit T_STORE_LOCAL - the READ instruction handles storage

				if (tk.t == TT_PUNC && tk.v[0] == ';') {
					adv();
					break;
				}
			}
			return;
		}

        if(tk.t==TT_ID){
            int idx = pr.get_local(tk.v);
            if(idx<0){ printf("Unknown var %s\n", tk.v); }
            int ty = pr.get_local_type(idx);
            adv();

            // Array element assignment
            if(tk.t==TT_PUNC && tk.v[0]=='['){
                pr.emit1(T_LOAD_LOCAL); pr.emit4(idx);  // 1. Push handle
                adv(); // past '['
                parse_expression();                      // 2. Push index
                expect("]");
                expect("=");
                parse_expression();                      // 3. Push value
                pr.emit1(T_STORE_ARRAY);                    // 4. Store
                expect(";");
                return;
            }

            expect("=");
            if(ty==2){
                if(tk.t==TT_STR){ const char* p=pr.add_lit(tk.v); pr.emit1(T_PUSH_STR); pr.emit4((int)p); adv(); }
                else if(tk.t==TT_KW && simple_strcmp(tk.v,"argv")==0){ adv(); expect("("); parse_expression(); expect(")"); pr.emit1(T_PUSH_ARGV_PTR); }
                else if(tk.t==TT_ID){ int j=pr.get_local(tk.v); adv(); pr.emit1(T_LOAD_LOCAL); pr.emit4(j); }
                else { parse_expression(); }
            } else {
                parse_expression();
            }
            pr.emit1(T_STORE_LOCAL); pr.emit4(idx);
            expect(";");
            return;
        }

        // Expression statement
        parse_expression();
        pr.emit1(T_POP); // Pop unused result
        expect(";");
    }

    void parse_if(){
        adv(); expect("("); parse_expression(); expect(")");
        pr.emit1(T_JZ); int jz_at = pr.mark(); pr.emit4(0);
        parse_block();
        int has_else = (tk.t==TT_KW && simple_strcmp(tk.v,"else")==0);
        if(has_else){
            pr.emit1(T_JMP); int j_at = pr.mark(); pr.emit4(0);
            int here = pr.pc; pr.patch4(jz_at, here);
            adv(); // else
            parse_block();
            int end = pr.pc; pr.patch4(j_at, end);
        } else {
            int here = pr.pc; pr.patch4(jz_at, here);
        }
    }

    void parse_while(){
        adv(); expect("("); int cond_ip = pr.pc; parse_expression(); expect(")");
        pr.emit1(T_JZ); int jz_at = pr.mark(); pr.emit4(0);
        int brk_base=brk_cnt, cont_base=cont_cnt;
        parse_block();
        for(int i=cont_base;i<cont_cnt;i++){ pr.patch4(cont_pos[i], cond_ip); }
        cont_cnt = cont_base;
        pr.emit1(T_JMP); pr.emit4(cond_ip);
        int end_ip = pr.pc; pr.patch4(jz_at, end_ip);
        for(int i=brk_base;i<brk_cnt;i++){ pr.patch4(brk_pos[i], end_ip); }
        brk_cnt = brk_base;
    }

    void parse_block(){
        if(accept("{")){
            while(!(tk.t==TT_PUNC && tk.v[0]=='}') && tk.t!=TT_EOF) parse_stmt();
            expect("}");
        } else {
            parse_stmt();
        }
    }

    void parse_stmt(){
        if(tk.t==TT_KW && simple_strcmp(tk.v,"int")==0){ parse_decl(0); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"char")==0){ parse_decl(1); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"string")==0){ parse_decl(2); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"return")==0){ adv(); parse_expression(); pr.emit1(T_RET); expect(";"); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"if")==0){ parse_if(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"while")==0){ parse_while(); return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"break")==0){ adv(); expect(";"); pr.emit1(T_JMP); int at=pr.mark(); pr.emit4(0); brk_pos[brk_cnt++]=at; return; }
        if(tk.t==TT_KW && simple_strcmp(tk.v,"continue")==0){ adv(); expect(";"); pr.emit1(T_JMP); int at=pr.mark(); pr.emit4(0); cont_pos[cont_cnt++]=at; return; }
        parse_assign_or_coutcin();
    }

    int compile(const char* source){
        lx.init(source); adv();
        if(!(tk.t==TT_KW && simple_strcmp(tk.v,"int")==0)) { printf("Expected 'int' at start\n"); return -1; }
        adv();
        if(!(tk.t==TT_ID && simple_strcmp(tk.v,"main")==0)){ printf("Expected main\n"); return -1; }
        adv(); expect("("); expect(")"); parse_block();
        pr.emit1(T_PUSH_IMM); pr.emit4(0); pr.emit1(T_RET);
        return pr.pc;
    }
};

// ============================================================
// MODIFIED TinyVM FOR PARTIAL COMPUTING
// ============================================================
struct TinyVM {
    static const int STK_MAX = 1024;
    int   stk[STK_MAX]; int sp=0;
    int   locals[TProgram::LOC_MAX];
    int   argc; const char** argv;
    TProgram* P;
    char str_in[256];
    uint64_t ahci_base; int port; // for file I/O
    int bound_window_idx = -1; 
	int pending_store_idx = 0;  // Where to store READ result

    // --- EXECUTION STATE FOR PARTIAL COMPUTING ---
    int ip = 0;             // Instruction Pointer (Persistent)
    bool is_running = false; // Is a program currently active?
    int exit_code = 0;      // Store result when finished
    // ---------------------------------------------
	// --- NEW: ASYNC INPUT STATE ---
	Window* bound_window = nullptr;   // instead of int bound_window_idx
    bool waiting_for_input = false;
    int  input_mode = 0;
    char input_buffer[256];
    int  input_pos = 0;
    // String pool for dynamic string management
    static const int STRING_POOL_SIZE = 8192;
    char string_pool[STRING_POOL_SIZE];
    int string_pool_top = 0;

    // Simple array management
    struct Array {
        int* data;
        int size;
        int capacity;
    };
    static const int MAX_ARRAYS = 64;
    Array arrays[MAX_ARRAYS];
    int array_count = 0;

    // Special array handle for hardware devices
    int hardware_array_handle = 0;

    inline void push(int v){ if(sp<STK_MAX) stk[sp++]=v; }
    inline int  pop(){ return sp?stk[--sp]:0; }

    // --- Helper Methods (Same as before) ---
    uint8_t mmio_read_8(uint64_t addr) { return *(volatile uint8_t*)addr; }
    uint16_t mmio_read_16(uint64_t addr) { return *(volatile uint16_t*)addr; }
    uint32_t mmio_read_32(uint64_t addr) { return *(volatile uint32_t*)addr; }
    uint64_t mmio_read_64(uint64_t addr) { return *(volatile uint64_t*)addr; }
    bool mmio_write_8(uint64_t addr, uint8_t value) { *(volatile uint8_t*)addr = value; return true; }
    bool mmio_write_16(uint64_t addr, uint16_t value) { *(volatile uint16_t*)addr = value; return true; }
    bool mmio_write_32(uint64_t addr, uint32_t value) { *(volatile uint32_t*)addr = value; return true; }
    bool mmio_write_64(uint64_t addr, uint64_t value) { *(volatile uint64_t*)addr = value; return true; }

    // String helpers
    const char* alloc_string(int len) {
        if(string_pool_top + len + 1 > STRING_POOL_SIZE) string_pool_top = 0; 
        if(string_pool_top + len + 1 > STRING_POOL_SIZE) return nullptr;
        char* result = &string_pool[string_pool_top];
        string_pool_top += len + 1;
        return result;
    }
    // (Simplified string helpers for brevity - assuming originals exist or use minimal versions)
    // Note: Ensure your original string helper functions (concat_strings, etc.) are inside here or available.
	  
    // Array helpers
    int alloc_array(int size) {
        if(array_count >= MAX_ARRAYS) return 0;
        int handle = array_count + 1;
        arrays[array_count].data = new int[size];
        arrays[array_count].size = size;
        arrays[array_count].capacity = size;
        for(int i=0; i<size; i++) arrays[array_count].data[i] = 0;
        array_count++;
        return handle;
    }
    Array* get_array(int handle) {
        if(handle > 0 && handle <= array_count) return &arrays[handle-1];
        return nullptr;
    }
    int resize_array(int handle, int new_size) {
        Array* arr = get_array(handle);
        if(!arr) return 0;
        int* new_data = new int[new_size];
        int copy_size = (arr->size < new_size) ? arr->size : new_size;
        for(int i=0; i<copy_size; i++) new_data[i] = arr->data[i];
        for(int i=copy_size; i<new_size; i++) new_data[i] = 0;
        delete[] arr->data;
        arr->data = new_data;
        arr->size = new_size;
        arr->capacity = new_size;
        return handle;
    }
    int create_device_info_array(int index) { return 0; /* stub */ }
    int create_hardware_array() { return 0; /* stub */ }
    int scan_hardware() { return hardware_count; }

    // --- NEW: INITIALIZE EXECUTION ---
     // UPDATED start_execution
      void start_execution(TProgram& prog,
                         int ac,
                         const char** av,
                         uint64_t base,
                         int p,
                         Window* win)   // NOTE: Window* not int
    {
        bound_window = win;
        P=&prog; argc=ac; argv=av; ahci_base=base; port=p;
        sp=0; ip=0; is_running=true; exit_code=0;
        waiting_for_input = false; input_mode = 0; input_pos = 0;
        array_count = 0; hardware_array_handle = 0; string_pool_top = 0;
        for (int i=0;i<TProgram::LOC_MAX;i++) locals[i]=0;

        for(int i = 0; i < P->loc_count; i++) {
            if(P->loc_type[i] == 3 || P->loc_type[i] == 4) {
                int arr_handle = alloc_array(P->loc_array_size[i]);
                locals[i] = arr_handle;
            }
        }
    }
	
	void vm_print(const char* s) {
		if (bound_window) {
			bound_window->console_print(s);  // Route to window!
		} else {
			printf(s);  // Fallback if no window
		}
	}

	void vm_putc(char c) {
		if (bound_window) {
			// Use put_char directly, which adds to current line without wrapping
			bound_window->put_char(c);
		} else {
			printf("%c", c);  // Fallback
		}
	}

    void feed_input(char c) {
		if (!waiting_for_input) return;
		
		if (c == '\n' || c == '\r') {
			input_buffer[input_pos] = 0;
			vm_putc('\n');
			
			if (input_mode == 1) {
				locals[pending_store_idx] = simple_atoi(input_buffer);
			}
			else if (input_mode == 2) {
				locals[pending_store_idx] = (unsigned char)input_buffer[0];
			}
			else if (input_mode == 3) {
				simple_strcpy(str_in, input_buffer);
				locals[pending_store_idx] = (int)str_in;
			}
			
			waiting_for_input = false;
			input_pos = 0;
			input_mode = 0;
			pending_store_idx = 0;
			
		} else if (c == '\b') {
			if (input_pos > 0) {
				input_pos--;
				input_buffer[input_pos] = 0;
				vm_putc('\b');
			}
		} else if (c >= 32 && c <= 126 && input_pos < 255) {
			input_buffer[input_pos++] = c;
			vm_putc(c);
		}
	}



    // --- NEW: TICK FUNCTION (Runs 'steps' instructions) ---
    // Returns: 1 if still running, 0 if finished
    int tick(int steps) {
        if (!is_running) return 0;
        if (waiting_for_input) return 1; // Still running, just paused

        int steps_done = 0;
        while(steps_done < steps && ip < P->pc && is_running){
			if (waiting_for_input) break;

            TOp op = (TOp)P->code[ip++];

            // PASTE YOUR ORIGINAL HUGE SWITCH STATEMENT HERE
            // IMPORTANT MODIFICATION: Replace "return rv;" with "exit_code = rv; is_running=false; return 0;"
            switch(op){
                case T_NOP: break;
                case T_PUSH_IMM: { int v= *(int*)&P->code[ip]; ip+=4; push(v); } break;
                case T_PUSH_STR: { int p= *(int*)&P->code[ip]; ip+=4; push(p); } break;
                case T_LOAD_LOCAL:{ int i=*(int*)&P->code[ip]; ip+=4; push(locals[i]); } break;
                case T_STORE_LOCAL:{ int i=*(int*)&P->code[ip]; ip+=4; locals[i]=pop(); } break;
                case T_POP: { if(sp) --sp; } break;
                case T_ADD: { int b=pop(), a=pop(); push(a+b); } break;
                case T_SUB: { int b=pop(), a=pop(); push(a-b); } break;
                case T_MUL: { int b=pop(), a=pop(); push(a*b); } break;
                case T_DIV: { int b=pop(), a=pop(); push(b? a/b:0); } break;
                case T_NEG: { int a=pop(); push(-a); } break;
                case T_EQ: { int b=pop(), a=pop(); push(a==b); } break;
                case T_NE: { int b=pop(), a=pop(); push(a!=b); } break;
                case T_LT: { int b=pop(), a=pop(); push(a<b); } break;
                case T_GT: { int b=pop(), a=pop(); push(a>b); } break;
                case T_LE: { int b=pop(), a=pop(); push(a<=b); } break;
                case T_GE: { int b=pop(), a=pop(); push(a>=b); } break;
                case T_JMP: { int t=*(int*)&P->code[ip]; ip=t; } break;
                case T_JZ:  { int t=*(int*)&P->code[ip]; ip+=4; int v=pop(); if(v==0) ip=t; } break;
                case T_JNZ: { int t=*(int*)&P->code[ip]; ip+=4; int v=pop(); if(v!=0) ip=t; } break;
                case T_PRINT_INT: {
					int v = pop();
					char buf[16];
					int_to_string(v, buf);
					printf("%s", buf);
				} break;

				case T_PRINT_CHAR: {
					int v = pop();
					char buf[2] = { (char)(v & 0xFF), 0 };
					printf("%s", buf);
				} break;

				case T_PRINT_STR: {
					const char* p = (const char*)pop();
					if (p) printf("%s", p);
				} break;

				case T_PRINT_ENDL: {
					printf("\n");
				} break;

				case T_PRINT_INT_ARRAY: {
					int handle = pop();
					Array* arr = get_array(handle);
					if (arr) {
						for (int i = 0; i < arr->size; i++) {
							char buf[16];
							int_to_string(arr->data[i], buf);
							printf("%s", buf);
							if (i < arr->size - 1) printf(", ");
						}
					}
				} break;

				case T_PRINT_STRING_ARRAY: {
					int handle = pop();
					// Handle string array printing
				} break;

				case T_READ_INT: {
					int idx = *(int*)&P->code[ip]; ip+=4;  // READ the variable index
					waiting_for_input = true;
					input_mode = 1;
					input_pos = 0;
					pending_store_idx = idx;  // Store where to write the result
					return 1;
				} break;

				case T_READ_CHAR: {
					int idx = *(int*)&P->code[ip]; ip+=4;
					waiting_for_input = true;
					input_mode = 2;
					input_pos = 0;
					pending_store_idx = idx;
					return 1;
				} break;

				case T_READ_STR: {
					int idx = *(int*)&P->code[ip]; ip+=4;
					waiting_for_input = true;
					input_mode = 3;
					input_pos = 0;
					pending_store_idx = idx;
					return 1;
				} break;
                // CRITICAL CHANGE: RETURN HANDLING
                case T_RET: { 
                    int rv=pop(); 
                    exit_code = rv; 
                    is_running = false; 
                    return 0; // Finished
                } break;
                
                default: break;
            }
            steps_done++;
        }
        
        if (ip >= P->pc && !waiting_for_input) {
            is_running = false;
            return 0;
        }

        return 1; // Still running
    }
};
// --- GLOBAL VM STATE ---

// --- GLOBAL PROCESS TABLE ---
#define MAX_PROCESSES 4
/* processes[] and prog_pool[] removed — RunContext/ExecContext own their
   own TinyVM+TProgram instances; these globals were dead weight (~400 KB). */

// ============================================================
// Enhanced Object I/O (TVM3 - with hardware support)
// ============================================================
struct TVMObject {
    static int save(uint64_t base, int port, const char* path, const TProgram& P){
        static unsigned char buf[ TProgram::CODE_MAX + TProgram::LIT_MAX + 128 ];
        int off=0;
        buf[off++]='T'; buf[off++]='V'; buf[off++]='M'; buf[off++]='3'; // Version 3 with hardware support
        *(int*)&buf[off]=P.pc; off+=4;
        *(int*)&buf[off]=P.lit_top; off+=4;
        *(int*)&buf[off]=P.loc_count; off+=4;
        simple_memcpy(&buf[off], P.code, P.pc); off+=P.pc;
        simple_memcpy(&buf[off], P.lit, P.lit_top); off+=P.lit_top;

        // Save local variable metadata (names, types, array sizes)
        for(int i = 0; i < P.loc_count; i++) {
            int name_len = tcc_strlen(P.loc_name[i]) + 1;
            simple_memcpy(&buf[off], P.loc_name[i], name_len); off += name_len;
            buf[off++] = P.loc_type[i];
            *(int*)&buf[off] = P.loc_array_size[i]; off += 4;
        }

        return fat32_write_file(path, buf, off);
    }

    // In SECTION 6, inside the TVMObject struct

static int load(uint64_t base, int port, const char* path, TProgram& P){
    // FIX: First, get the file's directory entry to find its true size.
    fat_dir_entry_t entry;
    uint32_t sector, offset;
    if (fat32_find_entry(path, &entry, &sector, &offset) != 0) {
        return -1; // File not found
    }
    uint32_t n = entry.file_size; // Use the REAL size from the filesystem.

    // Now we can read the file content.
    char* buf = fat32_read_file_as_string(path);
    if (!buf) {
        return -1; // Read failed
    }

    // The original buggy line is no longer needed.
    // int n = tcc_strlen(buf);  

    if (n < 16) { 
        delete[] buf; 
        return -1; 
    }
    if (!(buf[0] == 'T' && buf[1] == 'V' && buf[2] == 'M' && (buf[3] == '1' || buf[3] == '2' || buf[3] == '3'))) {
        delete[] buf;
        return -2;
    }
    int cp = *(int*)&buf[4], lp = *(int*)&buf[8], lc = *(int*)&buf[12];
    if (cp < 0 || cp > TProgram::CODE_MAX || lp < 0 || lp > TProgram::LIT_MAX || lc < 0 || lc > TProgram::LOC_MAX) {
        delete[] buf;
        return -3;
    }

    // The rest of the function now works correctly because 'n' is the true file size.
    P.pc = cp; P.lit_top = lp; P.loc_count = lc;
    int off = 16;
    simple_memcpy(P.code, &buf[off], cp); off += cp;
    simple_memcpy(P.lit, &buf[off], lp); off += lp;

    if (buf[3] >= '2') {
        for (int i = 0; i < lc; i++) {
            int name_len = 0;
            while (off + name_len < n && buf[off + name_len] != 0) name_len++;
            
            if (name_len < 32) {
                simple_memcpy(P.loc_name[i], &buf[off], name_len + 1);
            } else {
                P.loc_name[i][0] = 0;
            }
            off += name_len + 1;
            
            // Boundary check before reading type and size
            if (off + 5 > n) {
                delete[] buf;
                return -4; // Corrupt file, not enough data for metadata
            }
            
            P.loc_type[i] = buf[off++];
            P.loc_array_size[i] = *(int*)&buf[off]; off += 4;
        }
    } else {
        for (int i = 0; i < lc; i++) {
            P.loc_name[i][0] = 0;
            P.loc_type[i] = 0;
            P.loc_array_size[i] = 0;
        }
    }
    delete[] buf;
    return 0;
};
};

// ============================================================
// Enhanced compile/run entry points
// ============================================================
static int tinyvm_compile_to_obj(uint64_t ahci_base, int port, const char* src_path, const char* obj_path){
    char* srcbuf = fat32_read_file_as_string(src_path);
    if(!srcbuf){ printf("read fail\n"); return -1; }
    TCompiler C; int ok = C.compile(srcbuf);
    delete[] srcbuf;
    if(ok<0){ printf("Compilation failed!\n"); return -2; }
    int w = TVMObject::save(ahci_base, port, obj_path, C.pr);
    if(w<0){ printf("write fail\n"); return -3; }
    return 0;
}
// Updated wrapper (optional)
static int tinyvm_run_obj(uint64_t ahci_base, int port, const char* obj_path, int argc, const char** argv) {
    // Forward the actual parameters passed to this function
    cmd_run(ahci_base, port, obj_path);
    return 0;
}



// ============================================================
// Enhanced Shell glue with hardware discovery info
// ============================================================
extern "C" void cmd_compile(uint64_t ahci_base, int port, const char* filename){
    if (!filename) { printf("Usage: compile <file.cpp>\n"); return; }
    static char obj[64]; int i=0; while(filename[i] && i<60){ obj[i]=filename[i]; i++; }
    while(i>0 && obj[i-1] != '.') i--; obj[i]=0; simple_strcpy(&obj[i], "obj");
    printf("Compiling %s...\n", filename);
    int r = tinyvm_compile_to_obj(ahci_base, port, filename, obj);
    if(r==0) { printf("OK -> %s\n", obj); } else { printf("Compilation failed!\n"); }
}


// --- Command parsing helper ---
char* get_arg(char* args, int n) {
    char* p = args;

    // Loop to find the start of the Nth argument
    for (int i = 0; i < n; i++) {
        // Skip leading spaces for the current argument
        while (*p && *p == ' ') p++;

        // If we're at the end of the string, the requested arg doesn't exist
        if (*p == '\0') return nullptr;

        // Skip over the content of the current argument
        if (*p == '"') {
            p++; // Skip opening quote
            while (*p && *p != '"') p++;
            if (*p == '"') p++; // Skip closing quote
        } else {
            while (*p && *p != ' ') p++;
        }
    }

    // Now p is at the start of the Nth argument (or spaces before it)
    while (*p && *p == ' ') p++;
    if (*p == '\0') return nullptr;

    char* arg_start = p;
    if (*p == '"') {
        arg_start++; // The actual argument starts after the quote
        p++;
        while (*p && *p != '"') p++;
        if (*p == '"') *p = '\0'; // Place null terminator on the closing quote
    } else {
        while (*p && *p != ' ') p++;
        if (*p) *p = '\0'; // Place null terminator on the space
    }
    return arg_start;
}


    // Separate process tables
#define MAX_RUN_PROCESSES 4
#define MAX_EXEC_PROCESSES 4

// Context for RUN processes (disk-based execution)
struct RunContext {
    TProgram prog;           // Program code
    uint64_t ahci_base;      // Disk controller base
    int port;                // Disk port
    TinyVM vm;               // VM instance
    bool active;             // Is this slot in use
    char filename[64];       // Source filename for debugging
};

// Context for EXEC processes (memory-based execution)  
struct ExecContext {
    TProgram prog;           // Program code
    TinyVM vm;               // VM instance
    bool active;             // Is this slot in use
    int exec_id;             // Unique execution ID
};
static RunContext run_contexts[MAX_RUN_PROCESSES];
static ExecContext exec_contexts[MAX_EXEC_PROCESSES];
extern "C" void cmd_run(uint64_t ahci_base, int port, const char* filename) {
    if (!filename) { return; }
    // Find a free run slot
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (!run_contexts[i].active) {
            RunContext& ctx = run_contexts[i];
            ctx.active = false;
            ctx.ahci_base = ahci_base;
            ctx.port = port;
            strncpy(ctx.filename, filename, 63);
            ctx.filename[63] = '\0';
            if (TVMObject::load(ahci_base, port, filename, ctx.prog) != 0) {
                return;
            }
            const char* av[] = { filename, nullptr };
            ctx.vm.start_execution(ctx.prog, 1, av, ahci_base, port, nullptr);
            ctx.active = true;
            return;
        }
    }
}

	
	// List active run processes
void list_run_processes() {
    wm.print_to_focused("Active RUN processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (run_contexts[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: %s (IP=%d)\n", 
                     i, run_contexts[i].filename, run_contexts[i].vm.ip);
            wm.print_to_focused(msg);
            found = true;
        }
    }
    if (!found) {
        wm.print_to_focused("  (none)\n");
    }
}




// List active exec processes
void list_exec_processes() {
    wm.print_to_focused("Active EXEC processes:\n");
    bool found = false;
    for (int i = 0; i < MAX_EXEC_PROCESSES; i++) {
        if (exec_contexts[i].active) {
            char msg[128];
            snprintf(msg, 128, "  Slot %d: ID=%d (IP=%d)\n", 
                     i, exec_contexts[i].exec_id, exec_contexts[i].vm.ip);
            wm.print_to_focused(msg);
            found = true;
        }
    }
    if (!found) {
        wm.print_to_focused("  (none)\n");
    }
}

// Kill a run process
void kill_run_process(int slot) {
    if (slot >= 0 && slot < MAX_RUN_PROCESSES && run_contexts[slot].active) {
        run_contexts[slot].active = false;
        run_contexts[slot].vm.is_running = false;
        wm.print_to_focused("RUN process killed.\n");
    } else {
        wm.print_to_focused("Invalid RUN slot.\n");
    }
}

// Kill an exec process
void kill_exec_process(int slot) {
    if (slot >= 0 && slot < MAX_EXEC_PROCESSES && exec_contexts[slot].active) {
        exec_contexts[slot].active = false;
        exec_contexts[slot].vm.is_running = false;
        wm.print_to_focused("EXEC process killed.\n");
    } else {
        wm.print_to_focused("Invalid EXEC slot.\n");
    }
}
	
	

	
bool run_process_waiting_for_input() {
    for (int i = 0; i < MAX_RUN_PROCESSES; i++) {
        if (run_contexts[i].active && run_contexts[i].vm.waiting_for_input) {
            return true;
        }
    }
    return false;
}
		
	// =============================================================================
// ELF32 LOADER AND PROCESS EXECUTION
// =============================================================================

// ELF32 Header structures
#define EI_NIDENT 16
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS32 1
#define ELFDATA2LSB 1

#define ET_EXEC 2
#define EM_386 3

#define PT_LOAD 1
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((packed)) Elf32_Phdr;
