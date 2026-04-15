#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/avtab.h"
#include "avc.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "security.h"
#include "avc_ss.h"

static inline int avtab_hash(const struct avtab_key *keyp, u32 mask)
{
	static const u32 c1 = 0xcc9e2d51;
	static const u32 c2 = 0x1b873593;
	static const u32 r1 = 15;
	static const u32 r2 = 13;
	static const u32 m = 5;
	static const u32 n = 0xe6546b64;

	u32 hash = 0;

#define mix(input) { \
	u32 v = input; \
	v *= c1; \
	v = (v << r1) | (v >> (32 - r1)); \
	v *= c2; \
	hash ^= v; \
	hash = (hash << r2) | (hash >> (32 - r2)); \
	hash = hash * m + n; \
}

	mix(keyp->target_class);
	mix(keyp->target_type);
	mix(keyp->source_type);

#undef mix

	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash & mask;
}

extern struct selinux_state selinux_state;

static struct policydb *fmac_get_pdb(void)
{
	if (!selinux_state.policy)
		return NULL;
	return &rcu_dereference_protected(selinux_state.policy,
					  lockdep_is_held(&selinux_state.
							  policy_mutex)
	    )->policydb;
}

static void *pdb_symtab_search(struct symtab *s, const char *name)
{
	return symtab_search(s, name);
}

static bool is_redundant(struct avtab_node *node)
{
	switch (node->key.specified) {
	case AVTAB_AUDITDENY:
		return node->datum.u.data == ~0U;
	default:
		return node->datum.u.data == 0U;
	}
}

static void avtab_remove_node_safe(struct avtab *h, struct avtab_node *node)
{
	int hvalue;
	struct avtab_node *prev = NULL, *cur;

	if (!h || !h->htable)
		return;

	hvalue = avtab_hash(&node->key, h->mask);
	cur = h->htable[hvalue];
	while (cur) {
		if (cur == node)
			break;
		prev = cur;
		cur = cur->next;
	}
	if (!cur)
		return;

	if (prev)
		prev->next = node->next;
	else
		h->htable[hvalue] = node->next;
	h->nel--;

	kfree(node->datum.u.xperms);
	kfree(node);
}

int fmac_sepolicy_add_rule(const char *sname, const char *tname,
			   const char *cname, const char *pname,
			   int effect, bool invert)
{
	struct policydb *pdb;
	struct type_datum *src = NULL, *tgt = NULL;
	struct class_datum *cls = NULL;
	struct perm_datum *perm = NULL;
	struct avtab_key key;
	struct avtab_datum datum;
	struct avtab_node *node;
	int ret = 0;

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}

	if (sname && *sname) {
		src = pdb_symtab_search(&pdb->symtab[SYM_TYPES], sname);
		if (!src) {
			pr_warn("[selinux]: source type '%s' not found\n",
				sname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (tname && *tname) {
		tgt = pdb_symtab_search(&pdb->symtab[SYM_TYPES], tname);
		if (!tgt) {
			pr_warn("[selinux]: target type '%s' not found\n",
				tname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (cname && *cname) {
		cls = pdb_symtab_search(&pdb->symtab[SYM_CLASSES], cname);
		if (!cls) {
			pr_warn("[selinux]: class '%s' not found\n", cname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (pname && *pname) {
		if (!cls) {
			pr_warn("[selinux]: perm specified without class\n");
			ret = -EINVAL;
			goto out;
		}
		perm = pdb_symtab_search(&cls->permissions, pname);
		if (!perm && cls->comdatum)
			perm =
			    pdb_symtab_search(&cls->comdatum->permissions,
					      pname);
		if (!perm) {
			pr_warn
			    ("[selinux]: perm '%s' not found in class '%s'\n",
			     pname, cname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (!src || !tgt || !cls) {
		pr_warn
		    ("[selinux]: wildcard not supported in kernel add_rule, specify all fields\n");
		ret = -EINVAL;
		goto out;
	}

	key.source_type = src->value;
	key.target_type = tgt->value;
	key.target_class = cls->value;
	key.specified = effect;

	node = avtab_search_node(&pdb->te_avtab, &key);
	if (!node) {
		memset(&datum, 0, sizeof(datum));
		datum.u.data = (effect == AVTAB_AUDITDENY) ? ~0U : 0U;

		node = avtab_insert_nonunique(&pdb->te_avtab, &key, &datum);
		if (!node) {
			pr_err("[selinux]: avtab_insert_nonunique failed\n");
			ret = -ENOMEM;
			goto out;
		}
	}

	if (invert) {
		if (perm)
			node->datum.u.data &= ~(1U << (perm->value - 1));
		else
			node->datum.u.data = 0U;
	} else {
		if (perm)
			node->datum.u.data |= 1U << (perm->value - 1);
		else
			node->datum.u.data = ~0U;
	}

	if (is_redundant(node))
		avtab_remove_node_safe(&pdb->te_avtab, node);

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
		avc_ss_reset(0);
#else
		avc_ss_reset(selinux_state.avc, 0);
#endif
	return ret;
}
