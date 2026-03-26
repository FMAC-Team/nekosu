#include <linux/kallsyms.h>
#include <asm/syscall.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <fmac.h>

static struct mm_struct *init_mm_ptr;
syscall_fn_t *syscall_table;

// no export
struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

#define MAX_HOOKS 256

// no export
struct hook_entry {
	unsigned long addr;
	syscall_fn_t original;
};

static struct hook_entry hook_table[MAX_HOOKS];
static int hook_count = 0;
static DEFINE_SPINLOCK(hook_lock);

typedef int (*pmd_fn_t)(pmd_t * pmd, unsigned long addr, void *data);

int pmd_huge(pmd_t pmd)
{
	return pmd_val(pmd) && !(pmd_val(pmd) & PMD_TABLE_BIT);
}

int pud_huge(pud_t pud)
{
#if CONFIG_PGTABLE_LEVELS == 2
	return 0;
#else
	return pud_val(pud) && !(pud_val(pud) & PUD_TABLE_BIT);
#endif
}

static int change_page_range(pte_t *ptep, unsigned long addr, void *data)
{
	struct page_change_data *cdata = data;
	pte_t pte = READ_ONCE(*ptep);

	pte = clear_pte_bit(pte, cdata->clear_mask);
	pte = set_pte_bit(pte, cdata->set_mask);

	set_pte(ptep, pte);
	return 0;
}

static int change_pmd_range(pmd_t *pmdp, unsigned long addr, void *data)
{
	struct page_change_data *cdata = data;
	pmd_t pmd = READ_ONCE(*pmdp);

	pmd = clear_pmd_bit(pmd, cdata->clear_mask);
	pmd = set_pmd_bit(pmd, cdata->set_mask);

	set_pmd(pmdp, pmd);
	return 0;
}

static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
			      unsigned long addr, unsigned long end,
			      pte_fn_t fn, void *data, pgtbl_mod_mask *mask)
{
	pte_t *pte, *mapped_pte;
	int err = 0;
	spinlock_t *ptl;

	mapped_pte = pte = (mm == init_mm_ptr) ? pte_offset_kernel(pmd, addr) :
	    pte_offset_map_lock(mm, pmd, addr, &ptl);

	BUG_ON(pmd_huge(*pmd));
	arch_enter_lazy_mmu_mode();

	if (fn) {
		do {
			if (!pte_none(*pte)) {
				err = fn(pte++, addr, data);
				if (err)
					break;
			}
		} while (addr += PAGE_SIZE, addr != end);
	}
	*mask |= PGTBL_PTE_MODIFIED;

	arch_leave_lazy_mmu_mode();

	if (mm != init_mm_ptr)
		pte_unmap_unlock(mapped_pte, ptl);
	return err;
}

static int apply_to_pmd_range(struct mm_struct *mm, pud_t *pud,
			      unsigned long addr, unsigned long end,
			      pte_fn_t fn_pte, pmd_fn_t fn_pmd,
			      void *data, pgtbl_mod_mask *mask)
{
	pmd_t *pmd;
	unsigned long next;
	int err = 0;

	BUG_ON(pud_huge(*pud));

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none(*pmd))
			continue;

		if (pmd_leaf(*pmd)) {
			if (!fn_pmd || pmd_none(*pmd))
				continue;

			err = fn_pmd(pmd, addr, data);
			if (err)
				break;
		} else {
			if (!pmd_none(*pmd) && WARN_ON_ONCE(pmd_bad(*pmd)))
				continue;

			err = apply_to_pte_range(mm, pmd, addr, next, fn_pte,
						 data, mask);
			if (err)
				break;
		}
	} while (pmd++, addr = next, addr != end);

	return err;
}

static int apply_to_pud_range(struct mm_struct *mm, p4d_t *p4d,
			      unsigned long addr, unsigned long end,
			      pte_fn_t fn_pte, pmd_fn_t fn_pmd,
			      void *data, pgtbl_mod_mask *mask)
{
	pud_t *pud;
	unsigned long next;
	int err = 0;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		if (WARN_ON_ONCE(pud_leaf(*pud)))
			return -EINVAL;
		if (!pud_none(*pud) && WARN_ON_ONCE(pud_bad(*pud)))
			continue;
		err = apply_to_pmd_range(mm, pud, addr, next, fn_pte,
					 fn_pmd, data, mask);
		if (err)
			break;
	} while (pud++, addr = next, addr != end);

	return err;
}

static int apply_to_p4d_range(struct mm_struct *mm, pgd_t *pgd,
			      unsigned long addr, unsigned long end,
			      pte_fn_t fn_pte, pmd_fn_t fn_pmd,
			      void *data, pgtbl_mod_mask *mask)
{
	p4d_t *p4d;
	unsigned long next;
	int err = 0;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none(*p4d))
			continue;
		if (WARN_ON_ONCE(p4d_leaf(*p4d)))
			return -EINVAL;
		if (!p4d_none(*p4d) && WARN_ON_ONCE(p4d_bad(*p4d)))
			continue;
		err = apply_to_pud_range(mm, p4d, addr, next, fn_pte, fn_pmd,
					 data, mask);
		if (err)
			break;
	} while (p4d++, addr = next, addr != end);

	return err;
}

static int __apply_to_page_range(struct mm_struct *mm, unsigned long addr,
				 unsigned long size,
				 pte_fn_t fn_pte, pmd_fn_t fn_pmd, void *data)
{
	pgd_t *pgd;
	unsigned long start = addr, next;
	unsigned long end = addr + size;
	pgtbl_mod_mask mask = 0;
	int err = 0;

	if (WARN_ON(addr >= end))
		return -EINVAL;

	pgd = pgd_offset(mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(*pgd))
			continue;
		if (WARN_ON_ONCE(pgd_leaf(*pgd)))
			return -EINVAL;
		if (!pgd_none(*pgd) && WARN_ON_ONCE(pgd_bad(*pgd)))
			continue;
		err = apply_to_p4d_range(mm, pgd, addr, next, fn_pte, fn_pmd,
					 data, &mask);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	if (mask & ARCH_PAGE_TABLE_SYNC_MASK)
		arch_sync_kernel_mappings(start, start + size);

	return err;
}

static int __change_memory_common(unsigned long start, unsigned long size,
				  pgprot_t set_mask, pgprot_t clear_mask)
{
	struct page_change_data data;
	int ret;

	data.set_mask = set_mask;
	data.clear_mask = clear_mask;

	ret = __apply_to_page_range(init_mm_ptr, start, size,
				    &change_page_range, &change_pmd_range,
				    &data);
	if (ret)
		pr_info("__apply_to_page_range() failed: %d\n", ret);

	flush_tlb_kernel_range(start, start + size);
	return ret;
}

static int set_page_rw(unsigned long addr)
{
	vm_unmap_aliases();
	pr_info("setting page RW at VA: 0x%lx (PA: 0x%llx)\n",
		addr, (unsigned long long)virt_to_phys((void *)addr));
	return __change_memory_common(addr, PAGE_SIZE, __pgprot(PTE_WRITE),
				      __pgprot(PTE_RDONLY));
}

static int set_page_ro(unsigned long addr)
{
	vm_unmap_aliases();
	pr_info("setting page RO at VA: 0x%lx\n", addr);
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
	WRITE_ONCE(*(syscall_fn_t *) addr, hook_fn);

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

	WRITE_ONCE(*(syscall_fn_t *) addr, hook_table[i].original);
	hook_table[i] = hook_table[--hook_count];

	spin_unlock_irqrestore(&hook_lock, flags);

	ret = set_page_ro(page_addr);
	if (ret != 0)
		pr_err("set_page_ro() failed: %d\n", ret);

	return ret;
}

syscall_fn_t syscalltable_get_original(unsigned long addr)
{
	int i;
	unsigned long flags;
	syscall_fn_t orig = NULL;

	spin_lock_irqsave(&hook_lock, flags);
	for (i = 0; i < hook_count; i++) {
		if (hook_table[i].addr == addr) {
			orig = hook_table[i].original;
			break;
		}
	}
	spin_unlock_irqrestore(&hook_lock, flags);

	return orig;
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
