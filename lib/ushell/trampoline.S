
#define __REGS_OFFSETOF_R15       8
#define __REGS_PAD_SIZE           __REGS_OFFSETOF_R15
#define ENTRY(X)     .global X ; .type X, @function ; X:

.macro PUSH_CALLER_SAVE
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %rax
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
.endm

.macro POP_CALLER_SAVE
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rax
	popq %rcx
	popq %rdx
	popq %rsi
	popq %rdi
.endm

.text

ENTRY(ushell_start)
	PUSH_CALLER_SAVE
	subq $__REGS_PAD_SIZE, %rsp

	call ushell_main_thread

	addq $(__REGS_PAD_SIZE), %rsp
	POP_CALLER_SAVE

	cli
	movq $0, ushell_in_shell_context
	sti

	jmp *ushell_original_rip

