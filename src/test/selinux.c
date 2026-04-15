static void fmac_test_sepolicy(void)
{
    int ret;

    pr_info("[test]: starting sepolicy add_rule test\n");

    ret = fmac_sepolicy_add_rule(
        "shell", "shell_exec", "file", "execute",
        AVTAB_ALLOWED, false
    );
    pr_info("[test]: allow shell shell_exec:file execute => %d %s\n",
            ret, ret == 0 ? "OK" : "FAIL");

    ret = fmac_sepolicy_add_rule(
        "nonexistent_type_xyz", "shell_exec", "file", "execute",
        AVTAB_ALLOWED, false
    );
    pr_info("[test]: nonexistent src => %d %s\n",
            ret, ret == -ENOENT ? "OK (expected ENOENT)" : "FAIL");

    {
        struct policydb *pdb;
        struct type_datum *src, *tgt;
        struct class_datum *cls;
        struct avtab_key key;
        struct avtab_node *node;

        mutex_lock(&selinux_state.policy_mutex);
        pdb = &rcu_dereference_protected(
            selinux_state.policy,
            lockdep_is_held(&selinux_state.policy_mutex)
        )->policydb;

        src = symtab_search(&pdb->symtab[SYM_TYPES], "shell");
        tgt = symtab_search(&pdb->symtab[SYM_TYPES], "shell_exec");
        cls = symtab_search(&pdb->symtab[SYM_CLASSES], "file");

        if (src && tgt && cls) {
            key.source_type  = src->s.value;
            key.target_type  = tgt->s.value;
            key.target_class = cls->s.value;
            key.specified    = AVTAB_ALLOWED;

            node = avtab_search_node(&pdb->te_avtab, &key);
            if (node) {
                pr_info("[test]: avtab verify: node found, data=0x%08x\n",
                        node->datum.u.data);
            } else {
                pr_err("[test]: avtab verify: node NOT found!\n");
            }
        } else {
            pr_warn("[test]: avtab verify: type/class lookup failed"
                    " (src=%p tgt=%p cls=%p)\n", src, tgt, cls);
        }

        mutex_unlock(&selinux_state.policy_mutex);
    }

    pr_info("[test]: done\n");
}