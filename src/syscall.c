#include <linux/kallsyms.h>
#include <asm/syscall.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/spinlock.h>

#include <fmac.h>

static struct mm_struct *init_mm_ptr;
static syscall_fn_t *syscall_table;

struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

#define MAX_HOOKS 256

struct hook_entry {
	unsigned long addr;
	syscall_fn_t original;
};

static struct hook_entry hook_table[MAX_HOOKS];
static int hook_count = 0;
static DEFINE_SPINLOCK(hook_lock);

static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
{
	struct page_change_data *cdata = data;
	pte_t pte = READ_ONCE(*ptep);

	pte = clear_pte_bit(pte, cdata->clear_mask);
	pte = set_pte_bit(pte, cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

static int __change_memory_common(unsigned long start, unsigned long size,
				  pgprot_t set_mask, pgprot_t clear_mask)
{
	struct page_change_data data;
	int ret;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret =
	    apply_to_page_range(init_mm_ptr, start, size, change_page_range,
				&data);

	flush_tlb_kernel_range(start, start + size);
	return ret;
}

static int set_page_rw(unsigned long addr)
{
	return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE),
				      __pgprot(PTE_RDONLY));
}

static int set_page_ro(unsigned long addr)
{
	return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_RDONLY),
				      __pgprot(PTE_WRITE));
}

int syscalltable_hook(unsigned long addr, syscall_fn_t hook_fn)
{
	int ret;
	unsigned long page_addr = addr & PAGE_MASK;
	unsigned long flags;

	ret = set_page_rw(page_addr);
	if (ret != 0) {
		pr_err("set_page_rw() failed: %d\n", ret);
		return ret;
	}

	spin_lock_irqsave(&hook_lock, flags);

	if (hook_count >= MAX_HOOKS) {
		spin_unlock_irqrestore(&hook_lock, flags);
		set_page_ro(page_addr);
		return -ENOMEM;
	}

	hook_table[hook_count].addr = addr;
	hook_table[hook_count].original = *(syscall_fn_t *) addr;
	hook_count++;
	*(syscall_fn_t *) addr = hook_fn;

	spin_unlock_irqrestore(&hook_lock, flags);

	ret = set_page_ro(page_addr);
	if (ret != 0) {
		pr_err("set_page_ro() failed: %d\n", ret);
		return ret;
	}

	return 0;
}

int syscalltable_unhook(unsigned long addr)
{
	int ret, i;
	unsigned long page_addr = addr & PAGE_MASK;
	unsigned long flags;

	for (i = 0; i < hook_count; i++) {
		if (hook_table[i].addr == addr)
			break;
	}

	if (i == hook_count) {
		pr_err("unhook: addr not found\n");
		return -ENOENT;
	}

	ret = set_page_rw(page_addr);
	if (ret != 0) {
		pr_err("set_page_rw() failed: %d\n", ret);
		return ret;
	}

	spin_lock_irqsave(&hook_lock, flags);

	if (hook_table[i].addr != addr) {
		spin_unlock_irqrestore(&hook_lock, flags);
		set_page_ro(page_addr);
		pr_err("unhook: entry changed before lock\n");
		return -ENOENT;
	}

	*(syscall_fn_t *) addr = hook_table[i].original;
	hook_table[i] = hook_table[--hook_count];

	spin_unlock_irqrestore(&hook_lock, flags);

	ret = set_page_ro(page_addr);
	if (ret != 0)
		pr_err("set_page_ro() failed: %d\n", ret);

	return ret;
}

int syscalltable_init(void)
{
	init_mm_ptr = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	if (!init_mm_ptr) {
		pr_err("failed to find init_mm\n");
		return -ENOENT;
	}

	syscall_table = (syscall_fn_t *) kallsyms_lookup_name("sys_call_table");
	if (!syscall_table) {
		pr_err("failed to find sys_call_table\n");
		return -ENOENT;
	}
	pr_info("syscall hook init");
	return 0;
}

void syscalltable_exit(void)
{
	while (hook_count > 0) {
		syscalltable_unhook(hook_table[hook_count - 1].addr);
	}
}
