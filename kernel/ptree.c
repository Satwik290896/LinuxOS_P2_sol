#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/prinfo.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>

static inline void print_info(struct prinfo *cur_task_info,
	struct task_struct *p, int level)
{
	get_task_comm(cur_task_info->comm, p);
	cur_task_info->uid = __kuid_val(task_uid(p));
	cur_task_info->pid = task_pid_nr(p);
	cur_task_info->parent_pid = task_pid_nr(p->real_parent);
	cur_task_info->level = level;
}

static int do_level(struct prinfo *buf, int nr, int level,
	struct task_struct *root)
{
	struct task_struct *p = root;
	struct prinfo *cur_task_info;
	int count = 0;
	int curr_level = 0;
	bool going_up = false;

	while (!going_up || likely(p != root)) {
		if (!going_up && count < nr && curr_level == level) {
			cur_task_info = &buf[count];
			print_info(cur_task_info, p, curr_level);
		}

		if (!going_up && curr_level == level)
			++count;

		/* find the next task in DFS order */
		if (!going_up && !list_empty(&p->children)
			&& curr_level < level) {
			p = list_first_or_null_rcu(&p->children, struct task_struct,
					    sibling);
			curr_level += 1;
		} else if (likely(p != root)
			&& p->sibling.next != &p->real_parent->children) {
			p = list_entry_rcu((p)->sibling.next, struct task_struct, sibling);
			going_up = false;
		} else if (p == root) {
			going_up = true;
		} else {
			p = p->real_parent;
			going_up = true;
			curr_level -= 1;
		}
	}

	return count;
}

static struct task_struct *get_root(int root_pid)
{
	if (root_pid == 0)
		return &init_task;

	return find_task_by_vpid(root_pid);
}

static int do_ptree(struct prinfo *buf, int nr, int root_pid)
{
	int count = 0;
	int level_count = 0;
	int level = 0;
	struct task_struct *root;

	rcu_read_lock();
	root = get_root(root_pid);
	if (root == NULL) {
		rcu_read_unlock();
		return -ESRCH;
	}


	do {
		if (nr - count > 0)
			level_count = do_level(&buf[count], nr - count, level, root);
		else
			level_count = do_level(NULL, 0, level, root);

		count += level_count;
		level += 1;
	} while (level_count != 0);

	rcu_read_unlock();
	return count;
}

static void *alloc_memory_slow(size_t size, size_t *allocated)
{
	unsigned int fls_result = fls(size);
	void *mem = NULL;

	if (!fls_result) {
		WARN_ON(true);
		return mem;
	}

	size = 1 << (fls_result - 1);

	while (!mem && size) {
		mem = kmalloc(size, GFP_KERNEL);
		*allocated = size;
		size >>= 1;
	}

	return mem;
}

SYSCALL_DEFINE3(ptree, struct prinfo __user *, buf, int __user *, nr,
	int, root_pid)
{
	struct prinfo *kbuf;
	int knr, total, nr_allocated;
	size_t size, allocated;

	if (!buf || !nr)
		return -EINVAL;
	if (get_user(knr, nr))
		return -EFAULT;
	if (knr < 1)
		return -EINVAL;

	size = knr * sizeof(struct prinfo);
	kbuf = kmalloc(size, GFP_KERNEL);
	if (!kbuf) {
		kbuf = alloc_memory_slow(size, &allocated);
		if (!kbuf)
			return -ENOMEM;
		nr_allocated = allocated / sizeof(struct prinfo);
	} else {
		nr_allocated = knr;
	}

	total = do_ptree(kbuf, nr_allocated, root_pid);
	if (total < 0) {
		kfree(kbuf);
		return -EINVAL;
	}

	/* memory allocated is not enough */
	if (nr_allocated < knr && total > nr_allocated) {
		kfree(kbuf);
		return -ENOMEM;
	}

	knr = min(nr_allocated, total);
	size = knr * sizeof(struct prinfo);
	if (put_user(knr, nr) || copy_to_user(buf, kbuf, size)) {
		kfree(kbuf);
		return -EFAULT;
	}

	kfree(kbuf);
	return 0;
}
