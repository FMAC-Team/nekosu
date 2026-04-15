#include <linux/slab.h>
#include <linux/string.h>
#include <fmac.h>

#include "ss/policydb.h"
#include "ss/services.h"

static int add_type_to_policy(struct policydb *p, const char *name)
{
    struct type_datum *type;
    int rc;

    if (hashtab_search(p->p_types.table, name))
        return 0;

    type = kzalloc(sizeof(*type), GFP_KERNEL);
    if (!type)
        return -ENOMEM;

    type->primary = 1;

    type->value = ++p->p_types.nprim;

    rc = hashtab_insert(p->p_types.table, kstrdup(name, GFP_KERNEL), type);
    if (rc) {
        kfree(type);
        return rc;
    }

    return 0;
}

static int add_type_to_attr(struct policydb *p, const char *type_name, const char *attr_name)
{
    struct type_datum *type;
    struct type_datum *attr;

    type = hashtab_search(p->p_types.table, type_name);
    attr = hashtab_search(p->p_types.table, attr_name);

    if (!type || !attr)
        return -EINVAL;

    ebitmap_set_bit(&attr->types, type->value - 1, 1);

    return 0;
}

int sepolicy_add_domain(const char *name)
{
    struct policydb *p = &selinux_state.policydb;
    int rc;

    rc = add_type_to_policy(p, name);
    if (rc)
        return rc;

    rc = add_type_to_attr(p, name, "domain");
    if (rc)
        return rc;

    return 0;
}