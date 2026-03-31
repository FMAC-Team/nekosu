#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/namei.h>  
#include <linux/path.h> 
#include <linux/fs.h>   
#include <fmac.h>

// no export
struct hash_node {
	unsigned long ino;
	unsigned long status_bits;
	struct rhash_head rnode;
};

#define FMAC_BIT_DENY      0
#define FMAC_BIT_NOT_FOUND     1

static struct rhashtable fmac_rhashtable;

static const struct rhashtable_params fmac_rht_params = {
	.key_len = sizeof(unsigned long),
	.key_offset = offsetof(struct hash_node, ino),
	.head_offset = offsetof(struct hash_node, rnode),
	.automatic_shrinking = true,
};

static int get_ino_by_path(const char *path_str, unsigned long *ino)
{
	struct path path;
	int err;

	err = kern_path(path_str, LOOKUP_FOLLOW, &path);
	if (err)
		return err;

	if (path.dentry && d_backing_inode(path.dentry)) {
		*ino = d_backing_inode(path.dentry)->i_ino;
		err = 0;
	} else {
		err = -ENOENT;
	}

	path_put(&path);
	return err;
}

void set_node_bit(const char *key, int bit_nr)
{
	struct hash_node *node;
	unsigned long lookup_ino;

	if (get_ino_by_path(key, &lookup_ino) != 0) {
		pr_err("Path %s not found, cannot set bit.\n", key);
		return;
	}

	rcu_read_lock();
	node = rhashtable_lookup_fast(&fmac_rhashtable, &lookup_ino,
				      fmac_rht_params);
	if (node) {
		set_bit(bit_nr, &node->status_bits);
		pr_info("Inode %lu (Path: %s): Bit %d set.\n", lookup_ino, key, bit_nr);
	}
	rcu_read_unlock();
}

bool check_node_bit(const char *key, int bit_nr)
{
	struct hash_node *node;
	unsigned long lookup_ino;
	bool result = false;

	if (get_ino_by_path(key, &lookup_ino) != 0)
		return false;

	rcu_read_lock();
	node = rhashtable_lookup_fast(&fmac_rhashtable, &lookup_ino,
				      fmac_rht_params);
	if (node)
		result = test_bit(bit_nr, &node->status_bits);
	rcu_read_unlock();

	return result;
}

void insert_into_hash_table(const char *key, unsigned long status_bits)
{
	struct hash_node *new_node;
	unsigned long insert_ino;
	int err;

	if (get_ino_by_path(key, &insert_ino) != 0) {
		pr_err("Failed to resolve path %s to inode\n", key);
		return;
	}

	new_node = kzalloc(sizeof(struct hash_node), GFP_KERNEL);
	if (!new_node) {
		pr_err("Memory allocation failed\n");
		return;
	}

	new_node->ino = insert_ino;
	new_node->status_bits = status_bits;

	err = rhashtable_insert_fast(&fmac_rhashtable, &new_node->rnode,
				     fmac_rht_params);
	if (err) {
		pr_err("Failed to insert inode: %lu (Path: %s), err: %d\n", insert_ino, key, err);
		kfree(new_node);
		return;
	}

	pr_info("Inserted inode: %lu (Path: %s), status_bits: 0x%lx\n", insert_ino, key, status_bits);
}

void delete_from_hash_table(const char *key)
{
	struct hash_node *node;
	unsigned long lookup_ino;
	int err;

	if (get_ino_by_path(key, &lookup_ino) != 0) {
		pr_info("Path: %s not found, skipping deletion\n", key);
		return;
	}

	rcu_read_lock();
	node = rhashtable_lookup_fast(&fmac_rhashtable, &lookup_ino,
				      fmac_rht_params);
	rcu_read_unlock();

	if (!node) {
		pr_info("Inode: %lu (Path: %s) not found for deletion\n", lookup_ino, key);
		return;
	}

	err = rhashtable_remove_fast(&fmac_rhashtable, &node->rnode,
				     fmac_rht_params);
	if (!err) {
		kfree(node);
		pr_info("Deleted inode: %lu (Path: %s) from rhashtable\n", lookup_ino, key);
	}
}

struct hash_node *find_in_hash_table(const char *key)
{
	struct hash_node *node = NULL;
	unsigned long lookup_ino;

	if (get_ino_by_path(key, &lookup_ino) != 0)
		return NULL;

	rcu_read_lock();
	node = rhashtable_lookup_fast(&fmac_rhashtable, &lookup_ino,
				      fmac_rht_params);
	rcu_read_unlock();

	return node;
}

int rhash_init(void)
{
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
