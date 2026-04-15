#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/jhash.h>
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/hashtab.h"
#include "security.h"

static u32 symhash(const void *key, u32 size)
{
    const char *s = key;
    return jhash(s, strlen(s), 0) & (size - 1);
}

static int symcmp(const void *key1, const void *key2)
{
    return strcmp(key1, key2);
}

static const struct hashtab_key_params sym_params = {
    .hash = symhash,
    .cmp = symcmp,
};

static int add_type_to_attr(struct policydb *p, const char *type_name, const char *attr_name)
{
    struct type_datum *type;
    struct type_datum *attr;

    type = hashtab_search(p->p_types.table, type_name, sym_params);
    attr = hashtab_search(p->p_types.table, attr_name, sym_params);

    if (!type || !attr)
        return -EINVAL;

    ebitmap_set_bit(&attr->types, type->value - 1, 1);

    if (p->type_attr_map_array) {
        ebitmap_set_bit(&p->type_attr_map_array[type->value - 1], attr->value - 1, 1);
    }

    return 0;
}

static int add_type_to_policy(struct policydb *p, const char *name)
{
    struct type_datum *type;
    char *name_copy;
    int rc;
    uint32_t new_value;

    if (hashtab_search(p->p_types.table, name, sym_params))
        return 0;

    type = kzalloc(sizeof(*type), GFP_KERNEL);
    if (!type)
        return -ENOMEM;

    name_copy = kstrdup(name, GFP_KERNEL);
    if (!name_copy) {
        kfree(type);
        return -ENOMEM;
    }

    new_value = p->p_types.nprim + 1;
    type->primary = 1;
    type->value = new_value;

    void *tmp_names = krealloc(p->sym_val_to_name[SYM_TYPES], 
                               sizeof(char *) * new_value, GFP_KERNEL);
    if (!tmp_names) goto err;
    p->sym_val_to_name[SYM_TYPES] = tmp_names;
    p->sym_val_to_name[SYM_TYPES][new_value - 1] = name_copy;

    void *tmp_structs = krealloc(p->type_val_to_struct, 
                                 sizeof(struct type_datum *) * new_value, GFP_KERNEL);
    if (!tmp_structs) goto err;
    p->type_val_to_struct = tmp_structs;
    p->type_val_to_struct[new_value - 1] = type;

    void *tmp_map = krealloc(p->type_attr_map_array, 
                             sizeof(struct ebitmap) * new_value, GFP_KERNEL);
    if (!tmp_map) goto err;
    p->type_attr_map_array = tmp_map;
    ebitmap_init(&p->type_attr_map_array[new_value - 1]);

    rc = hashtab_insert(p->p_types.table, name_copy, type, sym_params);
    if (rc) goto err;

    p->p_types.nprim++;
    return 0;

err:
    kfree(name_copy);
    kfree(type);
    return -ENOMEM;
}

int sepolicy_add_domain(const char *name)
{
    struct selinux_policy *policy;
    struct policydb *p;
    int rc;

    policy = rcu_dereference_raw(selinux_state.policy);
    if (!policy)
        return -EINVAL;

    p = &policy->policydb;

    rc = add_type_to_policy(p, name);
    if (rc)
        return rc;

    rc = add_type_to_attr(p, name, "domain");
    return rc;
}