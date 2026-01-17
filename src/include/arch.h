#if defined(CONFIG_ARM64)

#    define SYSCALL_ARG0(regs) ((regs)->regs[0])
#    define SYSCALL_ARG1(regs) ((regs)->regs[1])
#    define SYSCALL_ARG2(regs) ((regs)->regs[2])
#    define SYSCALL_ARG3(regs) ((regs)->regs[3])

#elif defined(CONFIG_X86_64)

#    define SYSCALL_ARG0(regs) ((regs)->di)
#    define SYSCALL_ARG1(regs) ((regs)->si)
#    define SYSCALL_ARG2(regs) ((regs)->dx)
#    define SYSCALL_ARG3(regs) ((regs)->r10)

#else
#    error "Unsupported architecture"
#endif