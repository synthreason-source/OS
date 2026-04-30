#pragma once
// instrument_stub.h — no-op Bochs instrumentation macros.
// When bochs_glue.cpp is compiled (BOCHS=1), it is compiled with
// -DBOCHS_GLUE which prevents this file from stubbing out
// BX_INSTR_INTERRUPT — allowing bochs_glue.cpp to provide the real
// bx_instr_interrupt() function that intercepts guest int 0x80.
#ifndef BX_INSTRUMENT_H
#define BX_INSTRUMENT_H
#define BX_INSTR_PHY_ACCESS(a,b,c,d,e)
#define BX_INSTR_CACHE_CNTRL(a,b)
#define BX_INSTR_CLFLUSH(a,b,c)
#define BX_INSTR_TLB_CNTRL(a,b,c)
#define BX_INSTR_WRMSR(a,b,c)
#define BX_INSTR_OPCODE(a,b,c,d,e,f)
#define BX_INSTR_UCNEAR_BRANCH(a,b,c,d)
#define BX_INSTR_CNEAR_BRANCH_TAKEN(a,b,c)
#define BX_INSTR_CNEAR_BRANCH_NOT_TAKEN(a,b)
#define BX_INSTR_FAR_BRANCH(a,b,c,d,e,f)
#define BX_INSTR_FAR_BRANCH_ORIGIN()
#define BX_INSTR_IS_INT(a)    (0)
#define BX_INSTR_IS_RET(a)    (0)
#define BX_INSTR_IS_CALL(a)   (0)
#define BX_INSTR_IS_IRET(a)   (0)
#define BX_INSTR_IS_CALL_NEAR(a) (0)
#define BX_INSTR_IS_CALL_FAR(a)  (0)
#define BX_INSTR_INIT_ENV()
#define BX_INSTR_EXIT_ENV()
#define BX_INSTR_INITIALIZE(a)
#define BX_INSTR_EXIT(a)
#define BX_INSTR_RESET(a,b)
#define BX_INSTR_HLT(a)
#define BX_INSTR_MWAIT(a,b,c,d)
#define BX_INSTR_CNT(a)
#define BX_INSTR_BEFORE_EXECUTION(a,b)
#define BX_INSTR_AFTER_EXECUTION(a,b)
#define BX_INSTR_REPEAT_ITERATION(a,b)
#define BX_INSTR_INP(a,b)
#define BX_INSTR_INP2(a,b,c)
#define BX_INSTR_OUTP(a,b,c)
#define BX_INSTR_MEM_PHY_READ(a,b,c)
#define BX_INSTR_MEM_PHY_WRITE(a,b,c)
#define BX_INSTR_MEM_PHY_ACCESS(a,b,c,d)
#define BX_INSTR_LIN_ACCESS(a,b,c,d,e,f)
#define BX_INSTR_MEM_DATA(a,b,c,d,e)
#ifndef BOCHS_GLUE
// Only stub INTERRUPT when NOT building bochs_glue.cpp itself,
// so bochs_glue.cpp can provide the real bx_instr_interrupt().
#define BX_INSTR_INTERRUPT(a,b)
#endif
#define BX_INSTR_EXCEPTION(a,b,c)
#define BX_INSTR_HWINTERRUPT(a,b,c,d)
#endif
