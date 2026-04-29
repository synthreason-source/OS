// Stub implementations so the kernel links without Bochs
extern "C" {
    void bochs_cpu_init() {}
    void bochs_set_process_memory(unsigned char*, unsigned int, unsigned char*) {}
    void bochs_cpu_set_eip(unsigned int) {}
    void bochs_cpu_set_esp(unsigned int) {}
    int  bochs_cpu_tick(int) { return 0; }
    unsigned int bochs_cpu_get_eip() { return 0; }
    unsigned int bochs_cpu_geteip()  { return 0; }
    unsigned int bochs_cpu_get_eax() { return 0; }
}
