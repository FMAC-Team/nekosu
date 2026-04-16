#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <fmac.h>

#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/avtab.h"
#include "avc.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "security.h"
#include "avc_ss.h"
#include "xfrm.h"

static int avtab_remove_nohash(struct avtab *h, const struct avtab_key *key)
{
	u32 i;
	int removed = 0;

	if (!h || !h->htable)
		return -EINVAL;

	for (i = 0; i < h->nslot; i++) {
		struct avtab_node *cur = h->htable[i];
		struct avtab_node *prev = NULL;

		while (cur) {
			struct avtab_node *next = cur->next;

			if (cur->key.source_type == key->source_type &&
			    cur->key.target_type == key->target_type &&
			    cur->key.target_class == key->target_class &&
			    cur->key.specified == key->specified) {

				if (prev)
					prev->next = next;
				else
					h->htable[i] = next;

				h->nel--;

				if (cur->key.specified & AVTAB_XPERMS)
					kfree(cur->datum.u.xperms);

				kfree(cur);
				removed++;
			} else {
				prev = cur;
			}
			cur = next;
		}
	}
	return removed;
}

static struct policydb *fmac_get_pdb(void)
{
	if (!selinux_state.policy)
		return NULL;
	return &rcu_dereference_protected(selinux_state.policy,
					  lockdep_is_held
					  (&selinux_state.policy_mutex)
	    )->policydb;
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

int sepolicy_add_rule(const char *sname, const char *tname,
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
		src = symtab_search(&pdb->symtab[SYM_TYPES], sname);
		if (!src) {
			pr_warn("[selinux]: source type '%s' not found\n",
				sname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (tname && *tname) {
		tgt = symtab_search(&pdb->symtab[SYM_TYPES], tname);
		if (!tgt) {
			pr_warn("[selinux]: target type '%s' not found\n",
				tname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (cname && *cname) {
		cls = symtab_search(&pdb->symtab[SYM_CLASSES], cname);
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
		perm = symtab_search(&cls->permissions, pname);
		if (!perm && cls->comdatum)
			perm =
			    symtab_search(&cls->comdatum->permissions,
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
		avtab_remove_nohash(&pdb->te_avtab, node);

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
		avc_ss_reset(0);
		selnl_notify_policyload(0);
		selinux_status_update_policyload(0);
#else
		avc_ss_reset(selinux_state.avc, 0);
		selnl_notify_policyload(0);
		selinux_status_update_policyload(&selinux_state, 0);
#endif
		selinux_xfrm_notify_policyload();
	}
	return ret;
}
