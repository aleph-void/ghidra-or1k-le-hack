/* Relocation test: GOT-, GOTOFF- and GOTPC-model relocations (OpenRISC). */
extern int ext_var;
static int local_var = 5;
int global_var = 3;
int get_ext(void) { return ext_var; }
int get_local(void) { return local_var + global_var; }
int *addr_local(void) { return &local_var; }
int *addr_global(void) { return &global_var; }
