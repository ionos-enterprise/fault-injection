/*
 *  Fault injection framework.
 *
 *  Copyright (c) 2018 ProfitBricks GmbH.
 *  Authors: Roman Pen <roman.penyaev@profitbricks.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>

#define FAULT_INJECT_MODULE
#include "fault-injection.h"

#define FAULT_HEADER  "fault"
#define GROUP_HEADER  "group"
#define CLASS_HEADER  "class"
#define ADDR_HEADER   "address"
#define FUNC_HEADER   "function+off/size"
#define FILE_HEADER   "file:line"
#define FAULT_LINE_SZ 128 /* 126 letters, 1 newline, 1 null byte.
			   * before changing anything check
			   * 'format_fault_point' */

enum fault_type {
	DELAY_FAULT = 0, /* place first faults which do not generate
			  * errors to keep probing all of them */
	ERROR_FAULT,
	PANIC_FAULT,

	FAULTS_NUM  /* should be the last */
};

const char fault_type_chars[FAULTS_NUM] = {
	'D', 'E', 'P',
};

const char *fault_type_strings[FAULTS_NUM] = {
	"delay", "error", "panic",
};

struct fault_cfg {
	struct dentry      *dentry;
	const char         *name;
	enum fault_type     type;
	bool                enabled;
	bool                task_filter;
	atomic64_t          hits;
	atomic64_t          injected;
	atomic_t            times;
	unsigned short      probability;
	unsigned short      interval;
	struct fault_group *group;
	union {
		struct {
			unsigned int beg;
			unsigned int end;
		} delay_us;
		DECLARE_BITMAP(error_mask, FAULT_ERRORS_SZ);
	};
};

struct fault_group {
	struct fault_fs_ref  fs_ref;
	struct fault_inject *inj;
	struct dentry       *dentry;
	unsigned short       id;
	atomic_t             ref;
	struct list_head     list;
	struct mutex         lock;
	wait_queue_head_t    wait;
	struct fault_cfg     faults[FAULTS_NUM];
};

/* Keep in sync with asm constructor, see arch_static_branch */
struct fault_point {
	struct static_key   key;    /* always the first */
	unsigned int        magic;
	unsigned int        line;
	const char         *file;
	const char         *class;
	struct fault_group *group;
};

static inline void fault_fs_ref_init(struct fault_fs_ref *fs_ref)
{
	atomic_set(&fs_ref->ref, 0);
	init_waitqueue_head(&fs_ref->wait);
}

static inline void *priv_from_dentry(struct dentry *dentry)
{
	return dentry->d_inode->i_private;
}

static inline struct fault_fs_ref *ref_from_fault_inject(
	void *priv)
{
	struct fault_inject *inj = priv;

	return &inj->fs_ref;
}

static inline struct fault_fs_ref *ref_from_fault_group(
	void *priv)
{
	struct fault_group *group = priv;

	return &group->fs_ref;
}

static inline struct fault_fs_ref *ref_from_fault_cfg(
	void *priv)
{
	struct fault_cfg *cfg = priv;

	return &cfg->group->fs_ref;
}

/**
 * fault_fs_ref_get() - Returns private pointer of dentry if dentry is still
 *                      hashed.
 *
 * Why do we need this?  Because debugfs has stupid race when someone calls
 * debugfs_remove(), but another task performs file open and eventually
 * succeeds, but caller of debugfs_remove() is absolutely sure that dentry
 * was removed.  Here we check under the lock that dentry is still hashed,
 * if so the reference is increased, so even after the lock is released
 * out data is protected by the reference counter.
 */
static void *fault_fs_ref_get(
	struct dentry *dentry,
	struct fault_fs_ref *(*conv)(void *))
{
	struct fault_fs_ref *fs_ref;
	void *priv;

	spin_lock(&dentry->d_lock);
	if (d_unhashed(dentry))
		priv = NULL;
	else {
		priv = priv_from_dentry(dentry);
		fs_ref = conv(priv);
		atomic_inc(&fs_ref->ref);
	}
	spin_unlock(&dentry->d_lock);

	return priv;
}

static void fault_fs_ref_put(struct fault_fs_ref *fs_ref)
{
	BUG_ON(atomic_read(&fs_ref->ref) == 0);
	if (atomic_dec_and_test(&fs_ref->ref))
		wake_up(&fs_ref->wait);
}

static void fault_fs_ref_wait_grace_period(struct fault_fs_ref *fs_ref)
{
	wait_event(fs_ref->wait, atomic_read(&fs_ref->ref) == 0);
}

static void fault_dentry_remove(struct fault_fs_ref *fs_ref,
				struct dentry *dentry)
{
	debugfs_remove_recursive(dentry);
	fault_fs_ref_wait_grace_period(fs_ref);
}

static struct fault_group *group_allocate(struct fault_inject *inj,
					  unsigned int id)
{
	int i;
	struct fault_group *group;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	group->inj = inj;
	group->id = id;
	fault_fs_ref_init(&group->fs_ref);
	atomic_set(&group->ref, 0);
	INIT_LIST_HEAD(&group->list);
	mutex_init(&group->lock);
	init_waitqueue_head(&group->wait);

	BUILD_BUG_ON(ARRAY_SIZE(group->faults) != FAULTS_NUM);
	BUILD_BUG_ON(ARRAY_SIZE(group->faults) !=
		     ARRAY_SIZE(fault_type_strings));
	for (i = 0; i < ARRAY_SIZE(group->faults); i++) {
		group->faults[i]     = (struct fault_cfg) {
			.type        = (enum fault_type)i,
			.name        = fault_type_strings[i],
			.enabled     = false,
			.task_filter = false,
			.hits        = ATOMIC64_INIT(0),
			.injected    = ATOMIC64_INIT(0),
			.times       = ATOMIC_INIT(-1),
			.probability = 100,
			.interval    = 1,
			.delay_us    = {0, 0},
			.group       = group,
		};
	}

	return group;
}

static void group_free(struct fault_group *group)
{
	kfree(group);
}

static void __group_get(struct fault_group *group)
{
	BUG_ON(atomic_read(&group->ref) < 0);
	atomic_inc(&group->ref);
}

/**
 * group_get() - Gets group pointer from the fault point.
 *
 * If fault point has a group pointer, reference will be increased and group
 * will be returned. In case of error NULL will be returned.
 *
 * Function can be called from fault injection, thus any kind of contexts are
 * possible, even it can be called from interrupts.
 */
static struct fault_group *group_get(struct fault_inject *inj,
				     struct fault_point *fault)
{
	unsigned long flags;
	struct fault_group *group;

	spin_lock_irqsave(&inj->lock, flags);
	group = fault->group;
	if (likely(group)) {
		__group_get(group);
		BUG_ON(group->inj != inj);
	}
	spin_unlock_irqrestore(&inj->lock, flags);

	return group;
}

static bool group_put(struct fault_group *group)
{
	int ref;

	ref = atomic_sub_return(1, &group->ref);
	BUG_ON(ref < 0);

	if (ref == 0) {
		group_free(group);
		return true;
	} else if (ref == 1) {
		/*
		 * We do not wake up on 0 reference, since it is stupid to
		 * wait for group->ref == 0, because an object will be deleted
		 * underneath waiter. Here we do wake up on last reference.
		 */
		wake_up(&group->wait);
	}

	return false;
}

static void group_wait_last_ref(struct fault_group *group)
{
	wait_event(group->wait, atomic_read(&group->ref) == 1);
}

static bool group_list_del_and_put(struct fault_group *group)
{
	struct fault_group *group2put = NULL;

	spin_lock_irq(&group->inj->lock);
	if (likely(!list_empty(&group->list))) {
		list_del_init(&group->list);
		group2put = group;
	}
	spin_unlock_irq(&group->inj->lock);

	if (group2put) {
		group_put(group2put);
		return true;
	} else
		return false;
}

static bool __group_unlink_and_put(struct fault_group *group,
				   struct fault_point *fault)
{
	struct fault_group *group2put = NULL;

	spin_lock_irq(&group->inj->lock);
	if (fault->group == group) {
		group2put = fault->group;
		fault->group = NULL;
	}
	spin_unlock_irq(&group->inj->lock);

	if (group2put) {
		group_put(group2put);
		return true;
	} else
		return false;
}

static bool group_unlink_and_put(struct fault_group *group,
				 struct fault_point *fault)
{
	int i;
	bool ok;

	mutex_lock(&group->lock);
	ok = __group_unlink_and_put(group, fault);
	if (unlikely(!ok)) {
		mutex_unlock(&group->lock);
		return false;
	}
	for (i = 0; i < ARRAY_SIZE(group->faults); i++)
		if (group->faults[i].enabled)
			static_key_slow_dec(&fault->key);
	mutex_unlock(&group->lock);

	return true;
}

static int
group_unlink_from_fault(struct fault_inject *inj, struct fault_point *fault,
			struct jump_entry *entry, void *priv)
{
	bool ok;
	struct fault_group *group = priv;

	if (fault->group == group) {
		ok = group_unlink_and_put(group, fault);
		BUG_ON(!ok);
	}

	return 0;
}

static void group_list_add_and_get(struct fault_group *group)
{
	spin_lock_irq(&group->inj->lock);
	list_add(&group->list, &group->inj->list_groups);
	__group_get(group);
	spin_unlock_irq(&group->inj->lock);
}

static bool group_link_and_get(struct fault_group *group,
			       struct fault_point *fault)
{
	bool ok = false;

	spin_lock_irq(&group->inj->lock);
	if (fault->group == NULL) {
		fault->group = group;
		__group_get(group);
		ok = true;
	}
	spin_unlock_irq(&group->inj->lock);

	return ok;
}

static struct fault_group *group_find_and_get(struct fault_inject *inj,
					      unsigned int id)
{
	struct fault_group *group;

	spin_lock_irq(&inj->lock);
	list_for_each_entry(group, &inj->list_groups, list) {
		if (group->id == id) {
			BUG_ON(atomic_read(&group->ref) <= 0);
			__group_get(group);
			BUG_ON(group->inj != inj);
			spin_unlock_irq(&inj->lock);
			return group;
		}
	}
	spin_unlock_irq(&inj->lock);

	return NULL;
}

struct fault_iter {
	struct jump_entry  *start;
	struct jump_entry  *iter;
	struct jump_entry  *stop;
	struct fault_group *group;
};

static inline struct fault_point *__fault_iter_to_valid(
	struct fault_inject *inj,
	struct fault_iter *it)
{
	for (; it->iter < it->stop; it->iter++) {
		struct fault_point *f;

		f = (struct fault_point *)it->iter->key;
		if (f->magic != FAULT_MAGIC)
			continue;
		/*
		 * See 'jump_label_invalidate_module_init', if we are in
		 * a module init code - it will be set to zero. Skip it.\
		 */
		if (it->iter->code == 0x0)
			continue;
		/* Warn if somebody is naughty */
		WARN(within_module_init(it->iter->code, inj->mod),
		     "Fault was injected into module init code, addr 0x%016llx",
		     it->iter->code);

		/* Check group match if specified */
		if (it->group && it->group != f->group)
			continue;

		return f;
	}

	return NULL;
}

static inline struct fault_point *fault_iter_next(
	struct fault_inject *inj,
	struct fault_iter *it)
{
	if (it->iter >= it->stop)
		return NULL;

	it->iter++;

	return __fault_iter_to_valid(inj, it);
}

static inline struct fault_point *fault_iter_curr(
	struct fault_inject *inj,
	struct fault_iter *it)
{
	return __fault_iter_to_valid(inj, it);
}

static inline bool fault_iter_init(struct fault_inject *inj,
				   struct fault_iter *it,
				   struct fault_group *group,
				   unsigned int pos)
{
	if (inj->mod->num_jump_entries && pos >= inj->mod->num_jump_entries)
		return false;

	it->start = inj->mod->jump_entries;
	it->iter  = it->start + pos;
	it->stop  = it->start + inj->mod->num_jump_entries;
	it->group = group;

	return true;
}

static inline unsigned int fault_iter_pos(struct fault_iter *it)
{
	return (it->iter - it->start);
}

static int for_each_fault_inject_entry(struct fault_inject *inj,
				       int (*cb)(struct fault_inject *inj,
						 struct fault_point *fault,
						 struct jump_entry *entry,
						 void *priv),
				       void *priv)
{
	struct fault_iter it;
	struct fault_point *f;
	bool init;
	int rc;

	init = fault_iter_init(inj, &it, NULL /* no group */, 0);
	BUG_ON(!init);

	for (f = fault_iter_curr(inj, &it); f; f = fault_iter_next(inj, &it)) {
		rc = cb(inj, f, it.iter, priv);
		if (rc)
			return rc;
	}

	return 0;
}

struct fault_as_ret {
	struct fault_point *fault;
	void               *addr;
};

static int fault_by_target_addr(struct fault_inject *inj,
				struct fault_point *fault,
				struct jump_entry *entry,
				void *priv)
{
	struct fault_as_ret *ret = priv;

	if (entry->target == (unsigned long)ret->addr) {
		ret->fault = fault;
		return 1;
	}

	return 0;
}

static int fault_by_code_addr(struct fault_inject *inj,
			      struct fault_point *fault,
			      struct jump_entry *entry, void *priv)
{
	struct fault_as_ret *ret = priv;

	if (entry->code == (unsigned long)ret->addr) {
		ret->fault = fault;
		return 1;
	}

	return 0;
}

static struct fault_point *find_fault_by_target(struct fault_inject *inj,
						void *addr)
{
	struct fault_as_ret ret = {
		.addr  = addr,
		.fault = NULL,
	};

	for_each_fault_inject_entry(
		inj, fault_by_target_addr, &ret);

	return ret.fault;
}

static inline void __do_udelay(unsigned int delay_us)
{
	unsigned int d;

	while (delay_us) {
		d = min(delay_us, 1000u);
		udelay(d);
		delay_us -= d;
	}
}

static inline void do_fault_delay(struct fault_cfg *cfg)
{
	unsigned int beg, end, delay;

	/* Fetch them first to avoid non-atomic set. See @delay_us_store */
	beg = cfg->delay_us.beg;
	end = cfg->delay_us.end;

	if (end <= beg)
		delay = beg;
	else
		delay = beg + prandom_u32_max(end - beg + 1);

	__do_udelay(delay);
}

static inline bool task_may_inject_fault(struct fault_cfg *cfg,
					 struct task_struct *task)
{
/* This is Linux kernel configuration, see /proc/{pid}/make-it-fail */
#ifdef CONFIG_FAULT_INJECTION
	return !cfg->task_filter || (!in_interrupt() && task->make_it_fail);
#else
	return true;
#endif
}

static int inject_fault(struct fault_cfg *cfg)
{
	int ret;
	unsigned int bit_off, bit;
	unsigned long long hits, injected;

	hits = atomic64_add_return(1, &cfg->hits);

	if (!task_may_inject_fault(cfg, current))
		return 0;
	if (atomic_read(&cfg->times) == 0)
		return 0;
	BUG_ON(cfg->interval == 0);
	if ((hits - 1) % cfg->interval)
		return 0;
	BUG_ON(cfg->probability == 0);
	if (cfg->probability < 100 &&
	    cfg->probability <= prandom_u32() % 100)
		return 0;

	injected = atomic64_add_return(1, &cfg->injected);
	atomic_dec_if_positive(&cfg->times);

	switch (cfg->type) {
	case ERROR_FAULT:
		/* Except zero bit */
		bit_off = injected % (FAULT_ERRORS_SZ - 1) + 1;
		bit     = find_next_bit(cfg->error_mask,
					FAULT_ERRORS_SZ, bit_off);
		/* Start from the beginning */
		if (bit >= FAULT_ERRORS_SZ && bit_off > 1) {
			bit = find_next_bit(cfg->error_mask, bit_off, 1);
			if (bit >= bit_off)
				bit = FAULT_ERRORS_SZ;
		}

		if (bit < FAULT_ERRORS_SZ)
			ret = -bit;
		else
			ret = 0;
		break;
	case DELAY_FAULT:
		do_fault_delay(cfg);
		ret = 0;
		break;
	case PANIC_FAULT:
		panic("Panic from fault injection");
		ret = 0;
		break;
	default:
		BUG_ON(1);
		ret = 0;
		break;
	}

	return ret;
}

int inject_faults_by_target(struct fault_inject *inj, void *addr)
{
	int i, err = 0;
	struct fault_group *group;
	struct fault_cfg *cfg;
	struct fault_point *fp;

	fp = find_fault_by_target(inj, addr);
	BUG_ON(fp == NULL);

	group = group_get(inj, fp);
	if (!group)
		return 0;

	for (i = 0; i < ARRAY_SIZE(group->faults); i++) {
		cfg = &group->faults[i];
		if (!cfg->enabled)
			continue;
		err = inject_fault(cfg);
		if (err)
			goto out;

	}
out:
	group_put(group);
	return err;
}
EXPORT_SYMBOL_GPL(inject_faults_by_target);

static __printf(2, 3) int __seq_printf(struct seq_file *sf,
				       const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	if (sf) {
		i = sf->count;
		seq_vprintf(sf, fmt, args);
		i = sf->count - i;
	}
	else
		i = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	return i;
}

static int seq_format_header(struct seq_file *sf, struct fault_inject *inj)
{
	unsigned int width;

	BUG_ON(inj->max_func_sz < sizeof(FUNC_HEADER) - 1);

	width = inj->max_func_sz -
		(sizeof(FUNC_HEADER) - 1) +
		(sizeof(FILE_HEADER) - 1);

	return __seq_printf(sf, "%s %s %s %s            %s %*s\n",
			    FAULT_HEADER,
			    GROUP_HEADER,
			    CLASS_HEADER,
			    ADDR_HEADER,
			    FUNC_HEADER,
			    width,
			    FILE_HEADER);
}

static int seq_format_fault_point(struct seq_file *sf,
				  struct fault_inject *inj,
				  struct fault_point *fault,
				  struct jump_entry *entry)
{
	unsigned long func_sz;
	unsigned int  file_sz;
	const char *file = fault->file;
	struct fault_group *group;
	/* The following arrays should be in sync with FAULT_LINE_SZ */
	char fault_buf[6] = "-----";
	char group_buf[6] = "-----";
	char class_buf[6] = "-----";
	char addr_buf[19];
	char func_buf[65];
	char file_buf[25];
	char *tmp;

	BUILD_BUG_ON(sizeof(fault_buf) + sizeof(group_buf) +
		     sizeof(class_buf) + sizeof(addr_buf)  +
		     sizeof(func_buf)  + sizeof(file_buf)  + 1
		     != FAULT_LINE_SZ);

	group = group_get(inj, fault);
	if (group) {
		int i;

		BUILD_BUG_ON(ARRAY_SIZE(fault->group->faults) >=
			     sizeof(fault_buf));
		/* Fill in fault buffer */
		for (i = 0; i < ARRAY_SIZE(fault->group->faults); i++) {
			if (!fault->group->faults[i].enabled)
				continue;
			fault_buf[i] = fault_type_chars[
				fault->group->faults[i].type];
		}

		/* Fill in group buffer, never overflows */
		snprintf(group_buf, sizeof(group_buf), "%5u",
			 fault->group->id);

		group_put(group);
		group = NULL;
	}

	/* Fill in addr buffer, never overflows */
	snprintf(addr_buf, sizeof(addr_buf), "0x%016llx", entry->code);

	/* Fill in class buffer, can overflow */
	if (fault->class)
		snprintf(class_buf, sizeof(class_buf), "%5s", fault->class);

	/* Fill in func buffer */
	func_sz = snprintf(func_buf, sizeof(func_buf), "%pF",
			   (void *)entry->code);
	tmp = strchr(func_buf, ' ');
	if (tmp) {
		/* Skip module name, we really aware where we are */
		func_sz = tmp - func_buf;
		func_buf[func_sz] = '\0';
	}
	if (func_sz >= sizeof(func_buf)) {
		/* Overflow? Mark with dots and do size correction */
		memcpy(func_buf + sizeof(func_buf) - 4, "...", 3);
		func_sz = sizeof(func_buf) - 1;
	}

	/* Fill in file buffer */
	file = strrchr(fault->file, '/');
	if (file)
		file++;
	else
		file = fault->file;
	file_sz = snprintf(file_buf, sizeof(file_buf), "%s:%u",
			   file, fault->line);
	if (file_sz >= sizeof(file_buf)) {
		/* Overflow? Mark with dots and do size correction */
		memcpy(file_buf + sizeof(file_buf) - 4, "...", 3);
		file_sz = sizeof(file_buf) - 1;
	}

	/* Update max */
	if (inj->max_func_sz < func_sz)
		inj->max_func_sz = func_sz;

	return __seq_printf(sf, "%s %s %s %s %s %*s\n",
			    fault_buf,
			    group_buf,
			    class_buf,
			    addr_buf,
			    func_buf,
			    (unsigned int)(inj->max_func_sz - func_sz + file_sz),
			    file_buf);
}

static int dry_format_fault_point(struct fault_inject *inj,
				  struct fault_point *fault,
				  struct jump_entry *entry, void *notused)
{
	int rc;

	rc = seq_format_fault_point(NULL, inj, fault, entry);
	if (unlikely(rc < 0))
		return rc;
	return 0;
}


struct fault_line {
	void        *priv;
	struct mutex mutex;
	unsigned int loff;
	unsigned int len;
	char         buf[FAULT_LINE_SZ];
};

static inline struct fault_line *fault_line_create(void *priv)
{
	struct fault_line *line;

	line = kmalloc(sizeof(*line), GFP_KERNEL);
	if (unlikely(line == NULL))
		return NULL;

	mutex_init(&line->mutex);
	line->priv = priv;
	line->loff = 0;
	line->len  = 0;

	return line;
}

static ssize_t cache_user_line(struct fault_line *line,
			       const char __user *from,
			       size_t *off, size_t size)
{
	unsigned int len, res, loff;
	char *end;

	BUG_ON(*off >= size);
	BUG_ON(line->loff >= sizeof(line->buf));
	len = min(size - *off, sizeof(line->buf) - line->loff);
	res = copy_from_user(line->buf + line->loff, from + *off, len);
	if (res) {
		line->len = 0;
		line->loff = 0;
		return -EFAULT;
	}

	loff = line->loff;
	line->loff += len;
	end = strnstr(line->buf, "\n", line->loff);
	if (!end) {
		if (line->loff == sizeof(line->buf)) {
			line->len = 0;
			line->loff = 0;
			/* Buffer is over but where is \n? */
			return -EINVAL;
		}
		return *off + len;
	}
	end[0] = '\0';
	line->len  = end - line->buf;
	line->loff = 0;
	/* Advance the offset to the beginning of a new line */
	*off += line->len - loff + 1;

	return 0;
}

/**
 * The end of common fault code, a lot of debugfs stuff is the following.
 */

#define FAULT_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt, __conv)	\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	void *priv;							\
									\
	__simple_attr_check_format(__fmt, 0ull);			\
	priv = fault_fs_ref_get(file->f_path.dentry, __conv);		\
	if (unlikely(!priv))						\
		return -ENOENT;						\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static int __fops ## _close(struct inode *inode, struct file *file)	\
{									\
	simple_attr_release(inode, file);				\
	fault_fs_ref_put(__conv(priv_from_dentry(file->f_path.dentry)));\
	return 0;							\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = __fops ## _close,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
	.llseek	 = generic_file_llseek,					\
}

static int enable_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = cfg->enabled;

	return 0;
}

struct fault_point_enabled {
	struct fault_group *group;
	bool                to_enable;
};

static int __fault_point_enable(struct fault_inject *inj,
				struct fault_point *fault,
				struct jump_entry *entry, void *priv)
{
	struct fault_point_enabled *e = priv;

	if (e->group == fault->group) {
		if (e->to_enable)
			static_key_slow_inc(&fault->key);
		else
			static_key_slow_dec(&fault->key);
	}

	return 0;
}

static int enable_write_op(void *data, u64 val)
{
	struct fault_cfg *cfg = data;
	struct fault_point_enabled e;

	e.group     = cfg->group;
	e.to_enable = !!val;

	mutex_lock(&cfg->group->lock);
	if (likely(e.to_enable ^ cfg->enabled)) {
		for_each_fault_inject_entry(
			e.group->inj, __fault_point_enable, &e);
		cfg->enabled = e.to_enable;
	}
	mutex_unlock(&cfg->group->lock);

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(enable_fault_fops, enable_read_op,
		       enable_write_op, "%llu\n",
		       ref_from_fault_cfg);

static int hits_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = atomic64_read(&cfg->hits);

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(hits_fault_fops, hits_read_op,
		       NULL, "%llu\n",
		       ref_from_fault_cfg);

static int injected_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = atomic64_read(&cfg->injected);

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(injected_fault_fops, injected_read_op,
		       NULL, "%llu\n",
		       ref_from_fault_cfg);

static int times_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = atomic_read(&cfg->times);

	return 0;
}

static int times_write_op(void *data, u64 val)
{
	struct fault_cfg *cfg = data;

	if (val == 0)
		return -EINVAL;
	if ((int64_t)val < 0)
		val = -1;

	atomic_set(&cfg->times, val);

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(times_fault_fops, times_read_op,
		       times_write_op, "%lld\n",
		       ref_from_fault_cfg);

static int probability_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = cfg->probability;

	return 0;
}

static int probability_write_op(void *data, u64 val)
{
	struct fault_cfg *cfg = data;

	if (val == 0 || val > 100)
		return -EINVAL;

	cfg->probability = val;

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(probability_fault_fops, probability_read_op,
		       probability_write_op, "%llu\n",
		       ref_from_fault_cfg);

static int interval_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = cfg->interval;

	return 0;
}

static int interval_write_op(void *data, u64 val)
{
	struct fault_cfg *cfg = data;

	if (val == 0)
		return -EINVAL;

	cfg->interval = val;

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(interval_fault_fops, interval_read_op,
		       interval_write_op, "%llu\n",
		       ref_from_fault_cfg);

/* This is Linux kernel configuration, see /proc/{pid}/make-it-fail */
#ifdef CONFIG_FAULT_INJECTION

static int task_filter_read_op(void *data, u64 *val)
{
	struct fault_cfg *cfg = data;

	*val = cfg->task_filter;

	return 0;
}

static int task_filter_write_op(void *data, u64 val)
{
	struct fault_cfg *cfg = data;

	cfg->task_filter = !!val;

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(task_filter_fault_fops, task_filter_read_op,
		       task_filter_write_op, "%llu\n",
		       ref_from_fault_cfg);

#endif /* CONFIG_FAULT_INJECTION */

/**
 * strerror() - convert errno values to string
 * @err:	errno value		[input]
 *
 * The function converts errno values to strings.
 *
 * Unknown errno values are converted to their decimal
 * string representation.
 *
 * The function is not multithread safe as it places the
 * conversion of unknown errno values in a static variable.
 */
static const char *strerror(long err)
{
	/* decimal digits needed <= (2.5 * sizeof(err)) */
	static char buf[(sizeof(err) << 1) + sizeof(err)];

	if (unlikely(err >= 0)) {
		sprintf(buf, "%ld", err);
		return buf;
	}
	switch (err) {
#define CASE2STR(x)	case (x): return #x
	CASE2STR(-EPERM);
	CASE2STR(-ENOENT);
	CASE2STR(-ESRCH);
	CASE2STR(-EINTR);
	CASE2STR(-EIO);
	CASE2STR(-ENXIO);
	CASE2STR(-E2BIG);
	CASE2STR(-ENOEXEC);
	CASE2STR(-EBADF);
	CASE2STR(-ECHILD);
	CASE2STR(-EAGAIN);
	CASE2STR(-ENOMEM);
	CASE2STR(-EACCES);
	CASE2STR(-EFAULT);
	CASE2STR(-ENOTBLK);
	CASE2STR(-EBUSY);
	CASE2STR(-EEXIST);
	CASE2STR(-EXDEV);
	CASE2STR(-ENODEV);
	CASE2STR(-ENOTDIR);
	CASE2STR(-EISDIR);
	CASE2STR(-EINVAL);
	CASE2STR(-ENFILE);
	CASE2STR(-EMFILE);
	CASE2STR(-ENOTTY);
	CASE2STR(-ETXTBSY);
	CASE2STR(-EFBIG);
	CASE2STR(-ENOSPC);
	CASE2STR(-ESPIPE);
	CASE2STR(-EROFS);
	CASE2STR(-EMLINK);
	CASE2STR(-EPIPE);
	CASE2STR(-EDOM);
	CASE2STR(-ERANGE);
	CASE2STR(-EDEADLK);
	CASE2STR(-ENAMETOOLONG);
	CASE2STR(-ENOLCK);
	CASE2STR(-ENOSYS);
	CASE2STR(-ENOTEMPTY);
	CASE2STR(-ELOOP);
	CASE2STR(-ENOMSG);
	CASE2STR(-EIDRM);
	CASE2STR(-ECHRNG);
	CASE2STR(-EL2NSYNC);
	CASE2STR(-EL3HLT);
	CASE2STR(-EL3RST);
	CASE2STR(-ELNRNG);
	CASE2STR(-EUNATCH);
	CASE2STR(-ENOCSI);
	CASE2STR(-EL2HLT);
	CASE2STR(-EBADE);
	CASE2STR(-EBADR);
	CASE2STR(-EXFULL);
	CASE2STR(-ENOANO);
	CASE2STR(-EBADRQC);
	CASE2STR(-EBADSLT);
	CASE2STR(-EBFONT);
	CASE2STR(-ENOSTR);
	CASE2STR(-ENODATA);
	CASE2STR(-ETIME);
	CASE2STR(-ENOSR);
	CASE2STR(-ENONET);
	CASE2STR(-ENOPKG);
	CASE2STR(-EREMOTE);
	CASE2STR(-ENOLINK);
	CASE2STR(-EADV);
	CASE2STR(-ESRMNT);
	CASE2STR(-ECOMM);
	CASE2STR(-EPROTO);
	CASE2STR(-EMULTIHOP);
	CASE2STR(-EDOTDOT);
	CASE2STR(-EBADMSG);
	CASE2STR(-EOVERFLOW);
	CASE2STR(-ENOTUNIQ);
	CASE2STR(-EBADFD);
	CASE2STR(-EREMCHG);
	CASE2STR(-ELIBACC);
	CASE2STR(-ELIBBAD);
	CASE2STR(-ELIBSCN);
	CASE2STR(-ELIBMAX);
	CASE2STR(-ELIBEXEC);
	CASE2STR(-EILSEQ);
	CASE2STR(-ERESTART);
	CASE2STR(-ESTRPIPE);
	CASE2STR(-EUSERS);
	CASE2STR(-ENOTSOCK);
	CASE2STR(-EDESTADDRREQ);
	CASE2STR(-EMSGSIZE);
	CASE2STR(-EPROTOTYPE);
	CASE2STR(-ENOPROTOOPT);
	CASE2STR(-EPROTONOSUPPORT);
	CASE2STR(-ESOCKTNOSUPPORT);
	CASE2STR(-EOPNOTSUPP);
	CASE2STR(-EPFNOSUPPORT);
	CASE2STR(-EAFNOSUPPORT);
	CASE2STR(-EADDRINUSE);
	CASE2STR(-EADDRNOTAVAIL);
	CASE2STR(-ENETDOWN);
	CASE2STR(-ENETUNREACH);
	CASE2STR(-ENETRESET);
	CASE2STR(-ECONNABORTED);
	CASE2STR(-ECONNRESET);
	CASE2STR(-ENOBUFS);
	CASE2STR(-EISCONN);
	CASE2STR(-ENOTCONN);
	CASE2STR(-ESHUTDOWN);
	CASE2STR(-ETOOMANYREFS);
	CASE2STR(-ETIMEDOUT);
	CASE2STR(-ECONNREFUSED);
	CASE2STR(-EHOSTDOWN);
	CASE2STR(-EHOSTUNREACH);
	CASE2STR(-EALREADY);
	CASE2STR(-EINPROGRESS);
	CASE2STR(-ESTALE);
	CASE2STR(-EUCLEAN);
	CASE2STR(-ENOTNAM);
	CASE2STR(-ENAVAIL);
	CASE2STR(-EISNAM);
	CASE2STR(-EREMOTEIO);
	CASE2STR(-EDQUOT);
	CASE2STR(-ENOMEDIUM);
	CASE2STR(-EMEDIUMTYPE);
	CASE2STR(-ECANCELED);
	CASE2STR(-ENOKEY);
	CASE2STR(-EKEYEXPIRED);
	CASE2STR(-EKEYREVOKED);
	CASE2STR(-EKEYREJECTED);
	CASE2STR(-EOWNERDEAD);
	CASE2STR(-ENOTRECOVERABLE);
	CASE2STR(-ERFKILL);
	CASE2STR(-EHWPOISON);
	CASE2STR(-ERESTARTSYS);
	CASE2STR(-ERESTARTNOINTR);
	CASE2STR(-ERESTARTNOHAND);
	CASE2STR(-ENOIOCTLCMD);
	CASE2STR(-ERESTART_RESTARTBLOCK);
	CASE2STR(-EBADHANDLE);
	CASE2STR(-ENOTSYNC);
	CASE2STR(-EBADCOOKIE);
	CASE2STR(-ENOTSUPP);
	CASE2STR(-ETOOSMALL);
	CASE2STR(-ESERVERFAULT);
	CASE2STR(-EBADTYPE);
	CASE2STR(-EJUKEBOX);
	CASE2STR(-EIOCBQUEUED);
	default:
		break;
	}
	sprintf(buf, "%ld", err);
	return buf;
}

/**
 * str2error() - convert string to errno
 * @err_str:	string value		[input]
 *
 * The function converts string to errno.
 *
 * In case of unknown string 0 will be returned.
 *
 * This function does not care about performance and
 * simply executes 'strerror' for each errno
 * in range [-255, 0) and does strstr.
 */
static long str2error(const char *err_str)
{
	long err;
	const char *not_an_err;
	char first;

	if (unlikely(err_str == NULL))
		return 0;

	first = err_str[0];
	if (unlikely(first != '-' && first != 'E'))
		return 0;

	not_an_err = strerror(0) + (first == 'E');

	for (err = -255; err < 0; err++) {
		const char *e = strerror(err) + (first == 'E');

		if (e == not_an_err)
			continue;
		if (!strcmp(e, err_str))
			return err;
	}

	return 0;
}

static void *__errors_fault_find_next(struct fault_cfg *cfg, loff_t *pos)
{
	unsigned long bit;

	if (*pos >= FAULT_ERRORS_SZ)
		return NULL;

	bit = find_next_bit(cfg->error_mask, FAULT_ERRORS_SZ, *pos);
	/* 0 bit means succeess, can't be set */
	BUG_ON(bit == 0);
	if (bit >= FAULT_ERRORS_SZ)
		/* The end, no error */
		return NULL;

	*pos = bit;

	return (void *)bit;
}

static void *errors_fault_seq_start(struct seq_file *sf, loff_t *pos)
{
	struct fault_line *line = sf->private;
	struct fault_cfg *cfg = line->priv;

	return __errors_fault_find_next(cfg, pos);
}

static int errors_fault_seq_show(struct seq_file *sf, void *vp)
{
	unsigned long bit = (unsigned long)vp;

	__seq_printf(sf, "%s", strerror(-(long)bit));

	return 0;
}

static void *errors_fault_seq_next(struct seq_file *sf, void *vp, loff_t *pos)
{
	struct fault_line *line = sf->private;
	struct fault_cfg *cfg = line->priv;
	void *ret;

	++*pos;
	ret = __errors_fault_find_next(cfg, pos);
	if (ret)
		__seq_printf(sf, ",");
	else
		__seq_printf(sf, "\n");

	return ret;
}

static void errors_fault_seq_stop(struct seq_file *sf, void *vp)
{
}

static const struct seq_operations errors_fault_seq_ops = {
	.start	= errors_fault_seq_start,
	.show	= errors_fault_seq_show,
	.next	= errors_fault_seq_next,
	.stop	= errors_fault_seq_stop,
};

static int errors_fault_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct fault_cfg *cfg;
	struct fault_line *line;
	struct seq_file *sf;
	int rc;

	cfg = fault_fs_ref_get(dentry, ref_from_fault_cfg);
	if (unlikely(!cfg))
		return -ENOENT;

	rc = seq_open(file, &errors_fault_seq_ops);
	if (unlikely(rc)) {
		fault_fs_ref_put(&cfg->group->fs_ref);
		return rc;
	}

	line = fault_line_create(cfg);
	if (unlikely(line == NULL)) {
		seq_release(inode, file);
		fault_fs_ref_put(&cfg->group->fs_ref);
		return -ENOMEM;
	}

	sf = file->private_data;
	sf->private = line;

	return nonseekable_open(inode, file);
}

static int errors_fault_close(struct inode *inode, struct file *file)
{
	struct seq_file *sf = file->private_data;
	struct fault_line *line = sf->private;
	struct fault_cfg *cfg = line->priv;
	struct fault_group *group = cfg->group;

	seq_release(inode, file);
	fault_fs_ref_put(&group->fs_ref);
	kfree(line);

	return 0;
}

static ssize_t __errors_store(struct fault_line *line)
{
	const char *beg = line->buf, *end;
	unsigned int len;
	char buf[16];
	long err;
	struct fault_cfg *cfg = line->priv;
	bool done = false;
	DECLARE_BITMAP(error_mask, FAULT_ERRORS_SZ);

	bitmap_zero(error_mask, FAULT_ERRORS_SZ);
	while (!done) {
		end = strchr(beg, ',');
		if (!end) {
			done = true;
			end = line->buf + line->len;
			if (beg == end)
				break;
		}
		len = end - beg;
		if (len > sizeof(buf) - 1)
			return -EINVAL;
		memcpy(buf, beg, len);
		buf[len] = '\0';
		err = str2error(buf);
		if (err == 0)
			return -EINVAL;
		if (err >= FAULT_ERRORS_SZ)
			return -EINVAL;

		set_bit(abs(err), error_mask);

		beg = end + 1;
	}

	/* Do not care about concurrent access */
	bitmap_copy(cfg->error_mask, error_mask, FAULT_ERRORS_SZ);

	return 0;
}

static ssize_t errors_fault_write(struct file *file,
				  const char __user *u_buf,
				  size_t u_sz, loff_t *pos)
{
	struct seq_file *sf = file->private_data;
	struct fault_line *line = sf->private;
	size_t u_off = 0;
	int rc;

	if (u_sz == 0)
		return 0;

	rc = mutex_lock_interruptible(&line->mutex);
	if (unlikely(rc))
		return rc;
	rc = cache_user_line(line, u_buf, &u_off, u_sz);
	if (rc)
		goto out;

	rc = __errors_store(line);
out:
	mutex_unlock(&line->mutex);

	return rc ?: u_sz;
}

static const struct file_operations errors_fault_fops = {
	.owner	 = THIS_MODULE,
	.open    = errors_fault_open,
	.release = errors_fault_close,
	.read    = seq_read,
	.write	 = errors_fault_write,
	.llseek  = no_llseek,
};

static void *delay_us_fault_seq_start(struct seq_file *sf, loff_t *pos)
{
	return *pos ? NULL : sf->private;
}

static int delay_us_fault_seq_show(struct seq_file *sf, void *vp)
{
	struct fault_line *line = vp;
	struct fault_cfg *cfg = line->priv;

	__seq_printf(sf, "%u:%u\n",
		     cfg->delay_us.beg,
		     cfg->delay_us.end);

	return 0;
}

static void *delay_us_fault_seq_next(struct seq_file *sf, void *vp, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void delay_us_fault_seq_stop(struct seq_file *sf, void *vp)
{
}

static const struct seq_operations delay_us_fault_seq_ops = {
	.start	= delay_us_fault_seq_start,
	.show	= delay_us_fault_seq_show,
	.next	= delay_us_fault_seq_next,
	.stop	= delay_us_fault_seq_stop,
};

static int delay_us_fault_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct fault_cfg *cfg;
	struct fault_line *line;
	struct seq_file *sf;
	int rc;

	cfg = fault_fs_ref_get(dentry, ref_from_fault_cfg);
	if (unlikely(!cfg))
		return -ENOENT;

	rc = seq_open(file, &delay_us_fault_seq_ops);
	if (unlikely(rc)) {
		fault_fs_ref_put(&cfg->group->fs_ref);
		return rc;
	}

	line = fault_line_create(cfg);
	if (unlikely(line == NULL)) {
		seq_release(inode, file);
		fault_fs_ref_put(&cfg->group->fs_ref);
		return -ENOMEM;
	}

	sf = file->private_data;
	sf->private = line;

	return nonseekable_open(inode, file);
}

static int delay_us_fault_close(struct inode *inode, struct file *file)
{
	struct seq_file *sf = file->private_data;
	struct fault_line *line = sf->private;
	struct fault_cfg *cfg = line->priv;
	struct fault_group *group = cfg->group;

	seq_release(inode, file);
	fault_fs_ref_put(&group->fs_ref);
	kfree(line);

	return 0;
}

/**
 * __delay_us_store() - Parses delay_us input.
 *
 * Function accepts '%u:%u' range of delays or single '%u' value.
 * The idea is to do random us delay in some specified range.
 * If single value is passed then exactly this value will be used
 * for introducing delays.
 *
 * -EINVAL will be returned if parsing failed or the range is incorrect.
 */
static ssize_t __delay_us_store(struct fault_line *line)
{
	int rc;
	unsigned int beg, end;
	struct fault_cfg *cfg = line->priv;

	rc = sscanf(line->buf, "%u:%u", &beg, &end);
	if (rc < 1)
		return -EINVAL;
	else if (rc == 1)
		end = beg;
	if (end < beg)
		return -EINVAL;

	cfg->delay_us.beg = beg;
	cfg->delay_us.end = end;

	return 0;
}

static ssize_t delay_us_fault_write(struct file *file,
				    const char __user *u_buf,
				    size_t u_sz, loff_t *pos)
{
	struct seq_file *sf = file->private_data;
	struct fault_line *line = sf->private;
	size_t u_off = 0;
	int rc;

	if (u_sz == 0)
		return 0;

	rc = mutex_lock_interruptible(&line->mutex);
	if (unlikely(rc))
		return rc;
	rc = cache_user_line(line, u_buf, &u_off, u_sz);
	if (rc)
		goto out;

	rc = __delay_us_store(line);
out:
	mutex_unlock(&line->mutex);

	return rc ?: u_sz;
}

static const struct file_operations delay_us_fault_fops = {
	.owner	 = THIS_MODULE,
	.open    = delay_us_fault_open,
	.release = delay_us_fault_close,
	.read    = seq_read,
	.write	 = delay_us_fault_write,
	.llseek  = no_llseek,
};

static int group_add_fault_point(struct fault_group *group, void *addr)
{
	int i;
	bool ok;
	struct fault_as_ret ret = {
		.addr  = addr,
		.fault = NULL,
	};

	for_each_fault_inject_entry(
		group->inj, fault_by_code_addr, &ret);
	if (unlikely(ret.fault == NULL))
		return -EINVAL;

	mutex_lock(&group->lock);
	ok = group_link_and_get(group, ret.fault);
	if (unlikely(!ok)) {
		mutex_unlock(&group->lock);
		return -EINVAL;
	}
	BUG_ON(static_key_enabled(&ret.fault->key));
	for (i = 0; i < ARRAY_SIZE(group->faults); i++)
		if (group->faults[i].enabled)
			static_key_slow_inc(&ret.fault->key);
	mutex_unlock(&group->lock);

	return 0;
}

static int group_del_fault_point(struct fault_group *group, void *addr)
{
	bool ok;
	struct fault_as_ret ret = {
		.addr  = addr,
		.fault = NULL,
	};

	for_each_fault_inject_entry(
		group->inj, fault_by_code_addr, &ret);
	if (unlikely(ret.fault == NULL))
		return -EINVAL;
	ok = group_unlink_and_put(group, ret.fault);
	if (unlikely(!ok))
		return -ENOENT;

	return 0;
}

static ssize_t group_parse_address_for_each(struct fault_line *line,
					    const char __user *u_buf,
					    size_t u_sz,
					    int (*cb)(struct fault_group *,
						      void *))
{
	ssize_t rc;
	unsigned long long addr;
	size_t u_off = 0;
	const char *str;

	do {
		rc = cache_user_line(line, u_buf, &u_off, u_sz);
		if (rc)
			return rc;

		str = strnstr(line->buf, "0x", line->len);
		if (likely(str)) {
			rc = sscanf(str, "0x%llx", &addr);
			if (unlikely(rc != 1))
				return -EINVAL;

			rc = cb(line->priv, (void *)addr);
			if (unlikely(rc))
				return -EINVAL;
		}

	} while (u_off < u_sz);

	return u_sz;
}

static int generic_wr_fault_points_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct fault_group *group;
	struct fault_line *line;

	group = fault_fs_ref_get(dentry, ref_from_fault_group);
	if (unlikely(!group))
		return -ENOENT;

	line = fault_line_create(group);
	if (unlikely(line == NULL)) {
		fault_fs_ref_put(&group->fs_ref);
		return -ENOMEM;
	}

	file->private_data = line;

	return nonseekable_open(inode, file);
}

static int generic_wr_fault_points_close(struct inode *inode, struct file *file)
{
	struct fault_line *line = file->private_data;
	struct fault_group *group = line->priv;

	fault_fs_ref_put(&group->fs_ref);
	kfree(line);

	return 0;
}

static ssize_t add_fault_points_write(struct file *file,
				      const char __user *u_buf,
				      size_t u_sz, loff_t *pos)
{
	struct fault_line *line = file->private_data;
	int rc;

	if (u_sz == 0)
		return 0;

	rc = mutex_lock_interruptible(&line->mutex);
	if (unlikely(rc))
		return rc;
	rc = group_parse_address_for_each(line, u_buf, u_sz,
					  group_add_fault_point);
	mutex_unlock(&line->mutex);

	return rc;
}

static const struct file_operations add_fault_points_fops = {
	.owner	 = THIS_MODULE,
	.open	 = generic_wr_fault_points_open,
	.release = generic_wr_fault_points_close,
	.write	 = add_fault_points_write,
	.llseek	 = no_llseek,
};

static ssize_t del_fault_points_write(struct file *file,
				      const char __user *u_buf,
				      size_t u_sz, loff_t *pos)
{
	struct fault_line *line = file->private_data;
	int rc;

	if (u_sz == 0)
		return 0;

	rc = mutex_lock_interruptible(&line->mutex);
	if (unlikely(rc))
		return rc;
	rc = group_parse_address_for_each(line, u_buf, u_sz,
					  group_del_fault_point);
	mutex_unlock(&line->mutex);

	return rc;
}

static const struct file_operations del_fault_points_fops = {
	.owner	 = THIS_MODULE,
	.open	 = generic_wr_fault_points_open,
	.release = generic_wr_fault_points_close,
	.write	 = del_fault_points_write,
	.llseek	 = no_llseek,
};

struct fault_seq {
	struct fault_inject *inj;
	struct fault_group  *group;
	struct fault_iter    it;
};

static struct fault_point *seq_fault_iter_curr(struct fault_seq *fseq,
					       loff_t *pos)
{
	struct fault_point *fault;

	fault = fault_iter_curr(fseq->inj, &fseq->it);
	*pos = fault_iter_pos(&fseq->it);

	return fault;
}

static struct fault_point *seq_fault_iter_next(struct fault_seq *fseq,
					       loff_t *pos)
{
	struct fault_point *fault;

	fault = fault_iter_next(fseq->inj, &fseq->it);
	*pos = fault_iter_pos(&fseq->it);

	return fault;
}

static void *list_fault_points_seq_start(struct seq_file *sf, loff_t *pos)
{
	struct fault_seq *fseq = sf->private;
	bool init;

	init = fault_iter_init(fseq->inj, &fseq->it, fseq->group, *pos);
	if (unlikely(!init))
		return NULL;

	if (*pos == 0)
		seq_format_header(sf, fseq->inj);

	return seq_fault_iter_curr(fseq, pos);
}

static int list_fault_points_seq_show(struct seq_file *sf, void *vp)
{
	struct fault_seq *fseq = sf->private;
	struct fault_point *fault = vp;

	seq_format_fault_point(sf, fseq->inj, fault, fseq->it.iter);

	return 0;
}

static void *list_fault_points_seq_next(struct seq_file *sf, void *vp,
					loff_t *pos)
{
	struct fault_seq *fseq = sf->private;

	return seq_fault_iter_next(fseq, pos);
}

static void list_fault_points_seq_stop(struct seq_file *sf, void *vp)
{
}

static const struct seq_operations list_fault_points_seq_ops = {
	.start	= list_fault_points_seq_start,
	.show	= list_fault_points_seq_show,
	.next	= list_fault_points_seq_next,
	.stop	= list_fault_points_seq_stop,
};

static inline void fault_seq_init(struct fault_inject *inj,
				  struct fault_group *group,
				  struct fault_seq *fseq)
{
	fseq->inj = inj;
	fseq->group = group;
}

static struct fault_seq *fault_seq_create(struct fault_inject *inj,
					  struct fault_group *group)
{
	struct fault_seq *fseq;

	fseq = kmalloc(sizeof(*fseq), GFP_KERNEL);
	if (unlikely(fseq == NULL))
		return NULL;

	fault_seq_init(inj, group, fseq);
	return fseq;
}

static int __list_fault_points_open(struct inode *inode,
				    struct file *file,
				    struct fault_inject *inj,
				    struct fault_group *group)
{
	struct seq_file *sf;
	int rc;

	rc = seq_open(file, &list_fault_points_seq_ops);
	if (unlikely(rc))
		return rc;

	sf = file->private_data;
	sf->private = fault_seq_create(inj, group);
	if (unlikely(sf->private == NULL)) {
		seq_release(inode, file);
		return -ENOMEM;
	}

	return nonseekable_open(inode, file);
}

static int list_fault_points_root_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct fault_inject *inj;
	int rc;

	inj = fault_fs_ref_get(dentry, ref_from_fault_inject);
	if (unlikely(!inj))
		return -ENOENT;

	rc = __list_fault_points_open(inode, file, inj, NULL);
	if (unlikely(rc))
	    fault_fs_ref_put(&inj->fs_ref);

	return rc;
}

static int list_fault_points_group_open(struct inode *inode, struct file *file)
{
	struct dentry *dentry = file->f_path.dentry;
	struct fault_group *group;
	int rc;

	group = fault_fs_ref_get(dentry, ref_from_fault_group);
	if (unlikely(!group))
		return -ENOENT;

	rc = __list_fault_points_open(inode, file, group->inj, group);
	if (unlikely(rc))
	    fault_fs_ref_put(&group->fs_ref);

	return rc;
}

static int list_fault_points_close(struct inode *inode, struct file *file)
{
	struct seq_file *sf = file->private_data;
	struct fault_seq *fseq = sf->private;

	seq_release(inode, file);
	if (fseq->group)
		fault_fs_ref_put(&fseq->group->fs_ref);
	else
		fault_fs_ref_put(&fseq->inj->fs_ref);
	kfree(fseq);

	return 0;
}

static const struct file_operations list_fault_points_root_fops = {
	.owner	 = THIS_MODULE,
	.open    = list_fault_points_root_open,
	.release = list_fault_points_close,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

static const struct file_operations list_fault_points_group_fops = {
	.owner	 = THIS_MODULE,
	.open    = list_fault_points_group_open,
	.release = list_fault_points_close,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

static int next_group_read_op(void *data, u64 *val)
{
	struct fault_inject *inj = data;
	unsigned int bit;

	bit = find_first_zero_bit(inj->groups, FAULT_GROUPS_SZ);
	if (bit >= FAULT_GROUPS_SZ)
		return -EIO;
	*val = bit;

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(next_group_fops, next_group_read_op,
		       NULL, "%llu\n",
		       ref_from_fault_inject);

static int group_tie_with_debugfs(struct fault_group *group);
static void __group_wipe(struct fault_group *group);

static int create_group_write_op(void *data, u64 val)
{
	struct fault_inject *inj = data;
	struct fault_group *group;
	unsigned int bit;
	int rc;

	if (val >= FAULT_GROUPS_SZ)
		return -EINVAL;

	bit = val;
	if (test_and_set_bit(bit, inj->groups))
		return -EINVAL;

	group = group_allocate(inj, bit);
	if (unlikely(group == NULL)) {
		clear_bit(bit, inj->groups);
		return -EIO;
	}


	/*
	 * We have to get the reference to invoke normal group_put.
	 * See comments below.
	 */
	__group_get(group);
	rc = group_tie_with_debugfs(group);
	if (unlikely(rc)) {
		/*
		 * The thing is that debugfs entries can be partially created
		 * and someone can already put faults to that group and code
		 * can start to execute faults.  All we need is to wipe the
		 * group in generic way, i.e. traverse the faults and unlink
		 * them, and then put the group reference.  For sure reference
		 * can be not zero and actual freeing will happen when fault
		 * code puts the last reference.
		 */
		__group_wipe(group);
		group_put(group);
		return -EIO;
	}
	group_list_add_and_get(group);
	group_put(group);

	return 0;
}
FAULT_SIMPLE_ATTRIBUTE(create_group_fops, NULL,
		       create_group_write_op, "%llu\n",
		       ref_from_fault_inject);

static int group_wipe(struct fault_group *group);

static int delete_group_write_op(void *data, u64 val)
{
	struct fault_inject *inj = data;
	struct fault_group *group;
	unsigned int bit;
	int rc;

	if (val >= FAULT_GROUPS_SZ)
		return -EINVAL;

	bit = val;
	group = group_find_and_get(inj, bit);
	if (unlikely(!group))
		return -EINVAL;
	rc = group_wipe(group);
	group_put(group);

	return rc;
}
FAULT_SIMPLE_ATTRIBUTE(delete_group_fops, NULL,
		       delete_group_write_op, "%llu\n",
		       ref_from_fault_inject);

struct fault_debugfs_entry {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
};

#ifdef CONFIG_FAULT_INJECTION
#define TASK_FILTER_ENTRY						       \
	/* This is Linux kernel configuration, see /proc/{pid}/make-it-fail */ \
	{"task_filter", S_IWUSR | S_IRUGO,   &task_filter_fault_fops},
#else
#define TASK_FILTER_ENTRY
#endif

#define COMMON_FAULT_ENTRIES						\
	TASK_FILTER_ENTRY						\
	{"enable",      S_IWUSR | S_IRUGO,   &enable_fault_fops      }, \
	{"injected",              S_IRUGO,   &injected_fault_fops    }, \
	{"hits",                  S_IRUGO,   &hits_fault_fops        }, \
	{"times",       S_IWUSR | S_IRUGO,   &times_fault_fops       }, \
	{"probability", S_IWUSR | S_IRUGO,   &probability_fault_fops }, \
	{"interval",    S_IWUSR | S_IRUGO,   &interval_fault_fops    }

#define NULL_ENTRY {NULL, 0, NULL}

struct fault_debugfs_entry root_entries[] = {
	{"list_fault_points", S_IRUGO,   &list_fault_points_root_fops },
	{"next_group",        S_IRUGO,   &next_group_fops             },
	{"create_group",      S_IWUSR,   &create_group_fops           },
	{"delete_group",      S_IWUSR,   &delete_group_fops           },
	NULL_ENTRY
};

struct fault_debugfs_entry group_entries[] = {
	{"list_fault_points", S_IRUGO,   &list_fault_points_group_fops },
	{"add_fault_points",  S_IWUSR,   &add_fault_points_fops        },
	{"del_fault_points",  S_IWUSR,   &del_fault_points_fops        },
	NULL_ENTRY
};

struct fault_debugfs_entry delay_fault_entries[] = {
	COMMON_FAULT_ENTRIES,
	{"delay_us",    S_IWUSR | S_IRUGO,   &delay_us_fault_fops },
	NULL_ENTRY
};

struct fault_debugfs_entry error_fault_entries[] = {
	COMMON_FAULT_ENTRIES,
	{"errors",      S_IWUSR | S_IRUGO,   &errors_fault_fops    },
	NULL_ENTRY
};

struct fault_debugfs_entry panic_fault_entries[] = {
	COMMON_FAULT_ENTRIES,
	NULL_ENTRY
};

/* Keep the order in sync with fault_type and friends */
struct fault_debugfs_entry *all_fault_entries[] = {
	delay_fault_entries,
	error_fault_entries,
	panic_fault_entries
};

static struct dentry *fault_create_debugfs_entries(
					struct fault_fs_ref *fs_ref,
					struct fault_debugfs_entry *entries,
					struct dentry **dentries_out,
					const char *name, struct dentry *parent,
					void *priv)
{
	int i;
	struct dentry *root = NULL, *d;
	struct fault_debugfs_entry *e;

	d = debugfs_create_dir(name, parent);
	if (unlikely(IS_ERR_OR_NULL(d)))
		goto error;

	root = d;

	for (i = 0; ; i++) {
		if (entries[i].name == NULL)
			break;

		e = &entries[i];
		d = debugfs_create_file(e->name, e->mode, root, priv, e->fops);
		if (unlikely(IS_ERR_OR_NULL(d)))
			goto error;
		if (dentries_out)
			dentries_out[i] = d;
	}

	return root;

error:
	if (!IS_ERR(d))
		d = ERR_PTR(-ENOMEM);

	fault_dentry_remove(fs_ref, root);
	return d;
}

static int group_tie_with_debugfs(struct fault_group *group)
{
	int i = 0;
	struct fault_cfg *cfg;
	struct fault_debugfs_entry *fault_entries;
	struct fault_inject *inj = group->inj;
	struct dentry *dentry;
	char name[32];

	snprintf(name, sizeof(name), "%u", group->id);
	dentry = fault_create_debugfs_entries(&group->fs_ref, group_entries,
					      NULL, name, inj->root_dentry,
					      group);
	if (unlikely(IS_ERR(dentry)))
		return PTR_ERR(dentry);

	group->dentry = dentry;

	BUILD_BUG_ON(ARRAY_SIZE(group->faults) != ARRAY_SIZE(all_fault_entries));

	for (i = 0; i < ARRAY_SIZE(group->faults); i++) {
		cfg = &group->faults[i];
		fault_entries = all_fault_entries[i];

		dentry = fault_create_debugfs_entries(&group->fs_ref,
						      fault_entries, NULL,
						      cfg->name, group->dentry,
						      cfg);
		if (unlikely(IS_ERR(dentry))) {
			fault_dentry_remove(&group->fs_ref, group->dentry);
			group->dentry = NULL;
			return PTR_ERR(dentry);
		}

		cfg->dentry = dentry;
	}

	return 0;
}

/**
 * group_wipe() - prepares group for complete deletion
 *
 * Deletes group from list, unties group from debugfs, unlinks
 * group from each fault point, clears group bit from bitmap.
 *
 * After this sequence group is ready for last reference put.
 * For sure caller must hold the reference on this group, so
 * the caller is responsible for final put.
 */
static void __group_wipe(struct fault_group *group)
{
	int rc;

	BUG_ON(!list_empty(&group->list));

	rc = for_each_fault_inject_entry(
		group->inj, group_unlink_from_fault, group);
	BUG_ON(rc);

	rc = test_and_clear_bit(group->id, group->inj->groups);
	BUG_ON(!rc);
}

static int group_wipe(struct fault_group *group)
{
	if (!group_list_del_and_put(group))
		return -EINVAL;

	/*
	 * We are alone here, group was successfully removed from the list,
	 * so nobody can access and remove it twice.
	 */

	fault_dentry_remove(&group->fs_ref, group->dentry);
	__group_wipe(group);

	return 0;
}

/**
 * group_delete_all() - completely deletes all groups.
 *
 * Iterates over group list and wipes each group one by one,
 * then waits for last reference and makes final put. The caller
 * should guarantee that nobody will come and create/delete/modify
 * groups while we are here.
 */
static void group_delete_all(struct fault_inject *inj)
{
	int rc;
	bool done;
	unsigned int bit;
	struct fault_group *group, *t;

	spin_lock_irq(&inj->lock);
	list_for_each_entry_safe(group, t, &inj->list_groups, list) {
		__group_get(group);
		BUG_ON(group->inj != inj);
		spin_unlock_irq(&inj->lock);

		rc = group_wipe(group);
		BUG_ON(rc);
		group_wait_last_ref(group);
		done = group_put(group);
		BUG_ON(!done);

		spin_lock_irq(&inj->lock);
	}
	spin_unlock_irq(&inj->lock);

	/* Check all bits are cleared */
	bit = find_first_bit(inj->groups, FAULT_GROUPS_SZ);
	BUG_ON(bit < FAULT_GROUPS_SZ);
	BUG_ON(!list_empty(&inj->list_groups));
}

static void fault_inject_cleanup(struct fault_inject *inj)
{
	int i;

	/*
	 * Delete root dentries first to be sure nobody will
	 * come and create/delete groups
	 */
	for (i = 0; i < inj->attr_dent_num; i++)
		fault_dentry_remove(&inj->fs_ref, inj->attr_dentries[i]);
	kfree(inj->attr_dentries);
	group_delete_all(inj);
	fault_dentry_remove(&inj->fs_ref, inj->root_dentry);
}

static struct dentry *fi_dentry;

int fault_inject_register(struct fault_inject *inj, struct module *mod)
{
	int rc;

	inj->inited = false;
	if (unlikely(IS_ERR_OR_NULL(fi_dentry)))
	    return -ENOTSUPP;

	inj->mod = mod;
	inj->max_func_sz = sizeof(FUNC_HEADER) - 1;
	spin_lock_init(&inj->lock);
	INIT_LIST_HEAD(&inj->list_groups);
	fault_fs_ref_init(&inj->fs_ref);
	bitmap_zero(inj->groups, FAULT_GROUPS_SZ);

	inj->attr_dent_num = ARRAY_SIZE(root_entries) - 1;
	inj->attr_dentries = kmalloc_array(inj->attr_dent_num,
					   sizeof(*inj->attr_dentries),
					   GFP_KERNEL);
	if (unlikely(inj->attr_dentries == NULL))
		return -ENOMEM;

	inj->root_dentry =
		fault_create_debugfs_entries(&inj->fs_ref, root_entries,
					     inj->attr_dentries,
					     mod->name, fi_dentry, inj);
	if (unlikely(IS_ERR(inj->root_dentry))) {
		kfree(inj->attr_dentries);
		return PTR_ERR(inj->root_dentry);
	}

	/*
	 * Dry run each fault entry to setup correct max size of the
	 * function to have pretty format
	 */
	rc = for_each_fault_inject_entry(
		inj, dry_format_fault_point, NULL);
	if (unlikely(rc))
		goto err;

	/* Finally done */
	inj->inited = true;
	return 0;

err:
	fault_inject_cleanup(inj);
	return rc;
}
EXPORT_SYMBOL_GPL(fault_inject_register);

void fault_inject_unregister(struct fault_inject *inj)
{
	if (likely(!IS_ERR_OR_NULL(inj) && inj->inited)) {
		inj->inited = false;
		fault_inject_cleanup(inj);
	}
}
EXPORT_SYMBOL_GPL(fault_inject_unregister);

static int fault_inject_init(void)
{
	fi_dentry = debugfs_create_dir("fault_inject", NULL);
	if (unlikely(IS_ERR_OR_NULL(fi_dentry)))
		return -ENOTSUPP;
	return 0;
}

static void fault_inject_exit(void)
{
	BUG_ON(fi_dentry == NULL);
	debugfs_remove(fi_dentry);
}

module_init(fault_inject_init);
module_exit(fault_inject_exit);

MODULE_AUTHOR("Roman Pen <roman.penyaev@profitbricks.com>");
MODULE_DESCRIPTION("Improved fault injection framework");
MODULE_LICENSE("GPL");
MODULE_VERSION(__stringify(BUILD_VERSION));
