#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <fmac.h>

#define MAX_PATH_LEN 1024

// no export
struct hash_node {
	char key[MAX_PATH_LEN];
	unsigned long status_bits;
	struct rhash_head rnode;
};

#define FMAC_BIT_DENY      0
#define FMAC_BIT_NOT_FOUND     1

static struct rhashtable fmac_rhashtable;

static const struct rhashtable_params fmac_rht_params = {
	.key_len = MAX_PATH_LEN,
	.key_offset = offsetof(struct hash_node, key),
	.head_offset = offsetof(struct hash_node, rnode),
	.automatic_shrinking = true,
};

void set_node_bit(const char *key, int bit_nr)
{
	struct hash_node *node;
	char lookup_key[MAX_PATH_LEN] = { };

	strscpy(lookup_key, key, MAX_PATH_LEN);

	rcu_read_lock();
	node =
	    rhashtable_lookup_fast(&fmac_rhashtable, lookup_key,
				   fmac_rht_params);
	if (node) {
		set_bit(bit_nr, &node->status_bits);
		pr_info("Key %s: Bit %d set.\n", key, bit_nr);
	}
	rcu_read_unlock();
}

bool check_node_bit(const char *key, int bit_nr)
{
	struct hash_node *node;
	char lookup_key[MAX_PATH_LEN] = { };
	bool result = false;

	strscpy(lookup_key, key, MAX_PATH_LEN);

	rcu_read_lock();
	node =
	    rhashtable_lookup_fast(&fmac_rhashtable, lookup_key,
				   fmac_rht_params);
	if (node)
		result = test_bit(bit_nr, &node->status_bits);
	rcu_read_unlock();

	return result;
}

void insert_into_hash_table(const char *key, unsigned long status_bits)
{
	struct hash_node *new_node;
	int err;

	new_node = kzalloc(sizeof(struct hash_node), GFP_KERNEL);
	if (!new_node) {
		pr_err("Memory allocation failed\n");
		return;
	}

	strscpy(new_node->key, key, MAX_PATH_LEN);
	new_node->status_bits = status_bits;

	err =
	    rhashtable_insert_fast(&fmac_rhashtable, &new_node->rnode,
				   fmac_rht_params);
	if (err) {
		pr_err("Failed to insert key: %s, err: %d\n", key, err);
		kfree(new_node);
		return;
	}

	pr_info("Inserted key: %s, status_bits: 0x%lx\n", key, status_bits);
}

void delete_from_hash_table(const char *key)
{
	struct hash_node *node;
	char lookup_key[MAX_PATH_LEN] = { };
	int err;

	strscpy(lookup_key, key, MAX_PATH_LEN);

	rcu_read_lock();
	node =
	    rhashtable_lookup_fast(&fmac_rhashtable, lookup_key,
				   fmac_rht_params);
	rcu_read_unlock();

	if (!node) {
		pr_info("Key: %s not found for deletion\n", key);
		return;
	}

	err =
	    rhashtable_remove_fast(&fmac_rhashtable, &node->rnode,
				   fmac_rht_params);
	if (!err) {
		kfree(node);
		pr_info("Deleted key: %s from rhashtable\n", key);
	}
}

struct hash_node *find_in_hash_table(const char *key)
{
	struct hash_node *node;
	char lookup_key[MAX_PATH_LEN] = { };

	strscpy(lookup_key, key, MAX_PATH_LEN);

	rcu_read_lock();
	node =
	    rhashtable_lookup_fast(&fmac_rhashtable, lookup_key,
				   fmac_rht_params);
	rcu_read_unlock();

	return node;
}

int rhash_init(void)
{
//	struct hash_node *node;
	int err;

	err = rhashtable_init(&fmac_rhashtable, &fmac_rht_params);
	if (err) {
		pr_err("Failed to initialize rhashtable: %d\n", err);
		return err;
	}

	return 0;
}

static void my_rht_free_obj(void *ptr, void *arg)
{
	struct hash_node *node = ptr;
	kfree(node);
}

void rhash_exit(void)
{
	rhashtable_free_and_destroy(&fmac_rhashtable, my_rht_free_obj, NULL);
	pr_info("rhashtable module exited and memory freed\n");
}
