/*
 *  Fault injection framework.
 *
 *  Copyright (c) 2018 ProfitBricks GmbH.
 *  Authors: Roman Pen <roman.penyaev@profitbricks.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#ifndef __FAULT_INJECT_H
#define __FAULT_INJECT_H

#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/static_key.h>

#define FAULT_ERRORS_SZ 256
#define FAULT_GROUPS_SZ 256
#define	FAULT_MAGIC 0xa4dbd0dd

struct fault_inject;

typedef int (inj_fn)(struct fault_inject *inj, void *addr);
typedef int (reg_fn)(struct fault_inject *inj,  struct module *mod);
typedef int (unreg_fn)(struct fault_inject *inj);

struct fault_funcs {
	inj_fn   *inj;
	reg_fn   *reg;
	unreg_fn *unreg;
};

struct fault_fs_ref {
	wait_queue_head_t wait;
	atomic_t          ref;
};

struct fault_inject {
	struct fault_fs_ref fs_ref;
	struct module      *mod;
	struct dentry      *root_dentry;
	struct dentry     **attr_dentries;
	unsigned int        attr_dent_num;
	struct list_head    list_groups;
	DECLARE_BITMAP(     groups, FAULT_GROUPS_SZ);
	spinlock_t          lock;
	unsigned int        max_func_sz;
	bool                inited;
	struct fault_funcs  fn;
};

#ifndef FAULT_INJECT_MODULE

static inline int fault_inject_register(struct fault_inject *inj,
					struct module *mod)
{
	inj->fn.inj = __symbol_get("inject_faults_by_target");
	if (unlikely(inj->fn.inj == NULL))
		goto err_inj_get;
	inj->fn.reg = __symbol_get("fault_inject_register");
	if (unlikely(inj->fn.reg == NULL))
		goto err_reg_get;
	inj->fn.unreg = __symbol_get("fault_inject_unregister");
	if (unlikely(inj->fn.unreg == NULL))
		goto err_unreg_get;
	return inj->fn.reg(inj, mod);

err_unreg_get:
	__symbol_put("fault_inject_register");
err_reg_get:
	__symbol_put("inject_faults_by_target");
err_inj_get:
	inj->inited = false;
	return -ENODEV;
}

static inline void fault_inject_unregister(struct fault_inject *inj)
{
	if (likely(!IS_ERR_OR_NULL(inj) && inj->inited)) {
		inj->fn.unreg(inj);
		BUG_ON(inj->inited);
		__symbol_put("fault_inject_unregister");
		__symbol_put("fault_inject_register");
		__symbol_put("inject_faults_by_target");
	}
}

static inline int inject_faults_by_target(struct fault_inject *inj,
					  void *addr)
{
	BUG_ON(inj->fn.inj == NULL);
	return inj->fn.inj(inj, addr);
}

/**
 * The following repeats jump_label.h macro with only one major difference:
 * we do not depend on static_key in .bss, we create key on demand.  The
 * problem is that if caller function is inlined and is invoked from many
 * places static key in its turn is declared only once and thus we get
 * '1 key = N fault points' dependency.  To have exact match 1 key = 1 fault
 * we do this magic.
 */
static __always_inline void *
arch_fault_static_branch(const char *class, const char *file, unsigned int line)
{
	void *addr = NULL;
	const unsigned key_sz = sizeof(struct static_key);

	asm_volatile_goto(
		"1:"
		".byte " __stringify(STATIC_KEY_INIT_NOP) "\n\t"
		".pushsection .fault_inject, \"aw\" \n\t"
		_ASM_ALIGN "\n\t"
		"666:\n\t"
		".fill    %c0, 1, 0x00\n\t" /* zero key */
		".long "  __stringify(FAULT_MAGIC) "\n\t" /* magic */
		".long    %c1  \n\t" /* line number */
		_ASM_PTR "%c2  \n\t" /* file ptr */
		_ASM_PTR "%c3  \n\t" /* class ptr */
		_ASM_PTR "0x00 \n\t" /* group ptr */
		".popsection\n\t"
		".pushsection __jump_table,  \"aw\" \n\t"
		_ASM_ALIGN "\n\t"
		_ASM_PTR "1b, %l[l_yes], 666b \n\t"
		".popsection \n\t"
		:
		: "i"(key_sz), "i"(line), "i"(file), "i"(class)
		:
		: l_yes);

	return NULL;
l_yes:
	/*
	 * Unfortunately simple expression 'addr = &&l_yes;' does not
	 * work and instead of getting pointer exactly on l_yes label:
	 * "lea -0x7(%rip), %rsi", i.e. look back on 7 bytes of current
	 * %rip, gcc generates "lea 0x0(%rip), %rsi".  Ok, gcc, we expect
	 * assembler still works.
	 */
	asm volatile("1: lea 1b(%%rip),%0\n\t"
		     : "=r" (addr));

	return addr;
}

/**
 * INJECT_FAULTS() - Fault injection macro.
 *
 * Injects fault. If error was injected, the error code will be returned.
 * If delay was injected, zero should be returned.
 */
#define INJECT_FAULT(inj, class) ({					\
	int err = 0;							\
	void *true_br_addr;						\
									\
	true_br_addr = arch_fault_static_branch(class, __FILE__, __LINE__); \
	if (unlikely(true_br_addr))					\
		/* slow path */						\
		err = inject_faults_by_target(inj, true_br_addr);	\
	err;								\
})

/**
 * INJECT_FAULT_INT() - Fault injection macro.
 *
 * Injects fault. If fault was successfully injected, the 'func' parameter
 * is not called, and errno is returned. If fault was not fired - function
 * is called and its returning value will be returned as an integer.
 */
#define INJECT_FAULT_INT(inj, class, func) ({				\
	int err;							\
									\
	err = INJECT_FAULT(inj, class);					\
	if (likely(!err))						\
		err = func;						\
	err;								\
})

/**
 * INJECT_FAULT_NULL_PTR() - Fault injection macro.
 *
 * Injects fault. If fault was successfully injected, the 'func' parameter
 * is not called, and NULL pointer is returned. If fault was not fired -
 * function is called and its returning value will be returned as a pointer.
 */
#define INJECT_FAULT_NULL_PTR(inj, class, func) ({			\
	int err;							\
	void *p;							\
									\
	err = INJECT_FAULT(inj, class);					\
	if (unlikely(err))						\
		p = NULL;						\
	else								\
		p = func;						\
	p;								\
})

/**
 * INJECT_FAULT_ERR_PTR() - Fault injection macro.
 *
 * Injects fault. If fault was successfully injected, the 'func' parameter
 * is not called, and errno inside pointer is returned. If fault was not
 * fired - function is called and its returning value will be returned as
 * a pointer.
 */
#define INJECT_FAULT_ERR_PTR(inj, class, func) ({			\
	int err;							\
	void *p;							\
									\
	err = INJECT_FAULT(inj, class);					\
	if (unlikely(err))						\
		p = ERR_PTR(err);					\
	else								\
		p = func;						\
	p;								\
})

#endif /* FAULT_INJECT_MODULE */
#endif	/* !__FAULT_INJECT_H */
