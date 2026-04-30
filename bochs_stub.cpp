// bochs_stub.cpp — no-op stubs used when building without Bochs (BOCHS=0).
extern "C" {
    void bochs_cpu_init()                                             {}
    void bochs_set_process_memory(unsigned char*, unsigned int,
                                  unsigned int /*vaddr_base*/)        {}
    void bochs_set_brk(int, unsigned int)                             {}
    void bochs_activate_slot(int)                                     {}
    void bochs_register_io_callbacks(int,
             int  (*)(int),
             void (*)(int, char),
             void (*)(int, int))                                       {}
    void bochs_cpu_set_eip(unsigned int)                              {}
    void bochs_cpu_set_esp(unsigned int)                              {}
    int  bochs_cpu_tick(int)                            { return 0;  }
    unsigned int bochs_cpu_get_eip()                    { return 0;  }
    unsigned int bochs_cpu_geteip()                     { return 0;  }
    unsigned int bochs_cpu_get_eax()                    { return 0;  }
    // Returns false in stub mode (no Bochs, no real blocking)
    int bochs_process_wants_input(int)                  { return 0;  }
}
