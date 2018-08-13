/*
 *  Test scenarious for fault injection framework.
 *
 *  Copyright (C) 2015 Roman Pen <roman.penyaev@profitbricks.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 *
 *  If you have changed something, please do not forget to reflec
 *  these changes in fault injection documentation file: README
 */

#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/kthread.h>

#include <linux/debugfs.h>
#include <asm/uaccess.h>

#include "../fault_inject.h"

static struct dentry *test_dentry;
static struct fault_inject inj;
static struct task_struct *thr;
static bool reged;
static unsigned long long injected;
static DEFINE_MUTEX(lock);

#include "test_fault_inject.h"

static int register_write_op(void *data, u64 val)
{
	int rc = -EINVAL;

	mutex_lock(&lock);
	if (unlikely(reged))
		goto out;
	rc = fault_inject_register(&inj, THIS_MODULE);
	reged = !rc;
out:
	mutex_unlock(&lock);

	return rc;
}
DEFINE_SIMPLE_ATTRIBUTE(register_fops, NULL, register_write_op, "%llu\n");

static int unregister_write_op(void *data, u64 val)
{
	int rc = -EINVAL;

	mutex_lock(&lock);
	if (unlikely(!reged))
		goto out;
	fault_inject_unregister(&inj);
	reged = false;
	rc = 0;
out:
	mutex_unlock(&lock);

	return rc;
}
DEFINE_SIMPLE_ATTRIBUTE(unregister_fops, NULL, unregister_write_op, "%llu\n");

static __maybe_unused int fault_function(void)
{
	int rc = 0;

	mutex_lock(&lock);
	if (reged)
		rc = INJECT_FAULT(&inj, NULL);
	mutex_unlock(&lock);

	return rc;
}

static int run_fault(void *notused)
{
	int rc;

	while (!kthread_should_stop()) {
		CALL_FAULTS();
	}
	return 0;
}

static int start_thread_write_op(void *data, u64 val)
{
	int rc = -EINVAL;

	mutex_lock(&lock);

	if (unlikely(thr))
		goto out;
	thr = kthread_run(run_fault, NULL, "test_fault_injection");
	BUG_ON(IS_ERR(thr));
	rc = 0;
out:
	mutex_unlock(&lock);

	return rc;
}
DEFINE_SIMPLE_ATTRIBUTE(start_thread_fops, NULL, start_thread_write_op, "%llu\n");

static int stop_thread_write_op(void *data, u64 val)
{
	struct task_struct *t_thr;

	mutex_lock(&lock);
	t_thr = thr;
	thr = NULL;
	mutex_unlock(&lock);

	if (unlikely(!t_thr))
		return -EINVAL;

	kthread_stop(t_thr);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(stop_thread_fops, NULL, stop_thread_write_op, "%llu\n");

static int faults_injected_read_op(void *data, u64 *val)
{
	*val = injected;

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(faults_injected_fops, faults_injected_read_op, NULL, "%llu\n");

static int test_fault_inject_init(void)
{
	struct dentry *d;

	test_dentry = debugfs_create_dir("test_fault_inject", NULL);
	if (unlikely(IS_ERR_OR_NULL(test_dentry)))
		return -ENOTSUPP;

	d = debugfs_create_file("register", S_IWUSR, test_dentry,
				NULL, &register_fops);
	BUG_ON(IS_ERR_OR_NULL(d));

	d = debugfs_create_file("unregister", S_IWUSR, test_dentry,
				NULL, &unregister_fops);
	BUG_ON(IS_ERR_OR_NULL(d));

	d = debugfs_create_file("start_thread", S_IWUSR, test_dentry,
				NULL, &start_thread_fops);
	BUG_ON(IS_ERR_OR_NULL(d));

	d = debugfs_create_file("stop_thread", S_IWUSR, test_dentry,
				NULL, &stop_thread_fops);
	BUG_ON(IS_ERR_OR_NULL(d));

	d = debugfs_create_file("faults_injected", S_IRUGO, test_dentry,
				NULL, &faults_injected_fops);
	BUG_ON(IS_ERR_OR_NULL(d));

	return 0;
}
module_init(test_fault_inject_init);

static void test_fault_inject_exit(void)
{
	BUG_ON(test_dentry == NULL);
	debugfs_remove_recursive(test_dentry);

	if (thr)
		kthread_stop(thr);
	if (reged)
		fault_inject_unregister(&inj);

}
module_exit(test_fault_inject_exit);

MODULE_AUTHOR("Roman Pen <roman.penyaev@profitbricks.com>");
MODULE_DESCRIPTION("Some test scenarious for improved fault injection framework");
MODULE_LICENSE("GPL");
