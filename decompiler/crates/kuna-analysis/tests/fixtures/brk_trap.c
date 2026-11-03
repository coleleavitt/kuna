/* brk traps (option brktrap): clang lowers __builtin_trap() to brk #1. */
int checked_div(int a, int b)
{
    if (b == 0)
        __builtin_trap();
    return a / b;
}

void auth_fail(void)
{
    __asm__ volatile("brk #0xc471");
    __builtin_unreachable();
}

int _start(int a, int b)
{
    return checked_div(a, b);
}
