/*
 * pib_debugfs.c - Debugfs
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/export.h>

#include "pib.h"


static struct dentry *pib_debugfs_root;

static int register_dev(struct dentry *root, struct pib_dev *dev);
static void unregister_dev(struct pib_dev *dev);

static const char *debug_file_symbols[] = {
	[PIB_DEBUGFS_UCONTEXT] = "ucontext",
	[PIB_DEBUGFS_PD]       = "pd",
	[PIB_DEBUGFS_MR]       = "mr",
	[PIB_DEBUGFS_SRQ]      = "srq",
	[PIB_DEBUGFS_CQ]       = "cq",
};


struct pib_base_record {
	u32	obj_num;
	struct timespec	creation_time;
};


struct pib_ucontext_record {
	struct pib_base_record	base;
	pid_t	pid;
	pid_t	tgid;	
	char	comm[TASK_COMM_LEN];
};


struct pib_pd_record {
	struct pib_base_record	base;
};


struct pib_mr_record {
	struct pib_base_record	base;
	u32 pd_num;
	u64 start;
	u64 length;
	u32 lkey;
	u32 rkey;
	int access_flags;
};


struct pib_srq_record {
	struct pib_base_record	base;
	u32 pd_num;
	int state;
	int max_wqe;
	int nr_wqe;
};


struct pib_cq_record {
	struct pib_base_record	base;
};


struct pib_record_control {
	struct pib_dev	       *dev;
	enum pib_debugfs_type	type;
	int			count;
	int			pos;
	size_t			record_size;
	struct pib_base_record	records[];
};


static void *pib_debugfs_seq_start(struct seq_file *file, loff_t *pos)
{
	struct pib_record_control *control = file->private;

	if (*pos != 0)
		goto next;

	seq_puts(file, "OID  CREATIONTIME                               ");

	switch (control->type) {
	case PIB_DEBUGFS_UCONTEXT:
		seq_puts(file, "\n");
		break;

	case PIB_DEBUGFS_MR:
		seq_puts(file, "PD   START            LENGTH           LKEY     RKEY     AC\n");
		break;

	case PIB_DEBUGFS_SRQ:
		seq_puts(file, "PD   S   MAX   CUR\n");
		break;

	default:
		seq_puts(file, "\n");
		break;
	}

next:
	if (control->count <= *pos)
		return NULL;

	control->pos = *pos;

	return control;
}


static void *pib_debugfs_seq_next(struct seq_file *file, void *iter, loff_t *pos)
{
	struct pib_record_control *control = file->private;

	++*pos;

	if (control->count <= *pos)
		return NULL;

	control->pos = *pos;

	return iter;
}


static void pib_debugfs_seq_stop(struct seq_file *file, void *iter_ptr)
{
}


static int pib_debugfs_seq_show(struct seq_file *file, void *iter)
{
	struct pib_record_control *control = file->private;
	struct pib_base_record *record;
	struct timespec	time;
	struct tm tm;
	int pos;

	control = file->private;
	pos     = control->pos;

	record = (struct pib_base_record*)((unsigned long)control->records + (pos * control->record_size));

	time = record->creation_time;
	time_to_tm(time.tv_sec, 0, &tm);

	seq_printf(file, "%04x %10llu.%09lu (%04ld-%02d-%02d %02d:%02d:%02d)",
		   record->obj_num,
		   (unsigned long long)time.tv_sec, time.tv_nsec,
		   tm.tm_year + 1900, tm.tm_mon  + 1, tm.tm_mday,
		   tm.tm_hour, tm.tm_min, tm.tm_sec);

	switch (control->type) {

	case PIB_DEBUGFS_UCONTEXT: {
		struct pib_ucontext_record *ucontext_rec = (struct pib_ucontext_record *)record;
		seq_printf(file, " %5u %5u %s",
			   ucontext_rec->pid, ucontext_rec->tgid, ucontext_rec->comm);
		break;
	}

	case PIB_DEBUGFS_PD:
		break;

	case PIB_DEBUGFS_MR: {
		struct pib_mr_record *mr_rec = (struct pib_mr_record *)record;
		seq_printf(file, " %04x %016llx %016llx %08x %08x %x",
			   mr_rec->pd_num, mr_rec->start, mr_rec->length,
			   mr_rec->lkey, mr_rec->rkey, mr_rec->access_flags);
		break;
	}

	case PIB_DEBUGFS_SRQ: {
		struct pib_srq_record *srq_rec = (struct pib_srq_record *)record;
		seq_printf(file, " %04x %s %5u %5u",
			   srq_rec->pd_num,
			   ((srq_rec->state == PIB_STATE_OK) ? "OK " : "ERR"),
			   srq_rec->max_wqe, srq_rec->nr_wqe);
		break;
	}

	case PIB_DEBUGFS_CQ:
		break;

	default:
		BUG();
	}

	seq_putc(file, '\n');

	return 0;
}


static const struct seq_operations pib_debugfs_seq_ops = {
	.start = pib_debugfs_seq_start,
	.next  = pib_debugfs_seq_next,
	.stop  = pib_debugfs_seq_stop,
	.show  = pib_debugfs_seq_show,
};


static int pib_debugfs_open(struct inode *inode, struct file *file)
{
	int i, ret;
	struct pib_dev *dev;
	unsigned long flags;
	struct seq_file *seq;
	struct pib_debugfs_entry *entry;
	struct pib_record_control *control;

	entry = inode->i_private;
	dev   = entry->dev;

	switch (entry->type) {

	case PIB_DEBUGFS_UCONTEXT: {
		struct pib_ucontext *ucontext;
		struct pib_ucontext_record *records;

		control = vzalloc(sizeof(struct pib_record_control) +
				  dev->nr_ucontext * sizeof(struct pib_ucontext_record));
		if (!control)
			return -ENOMEM;

		records  = (struct pib_ucontext_record *)control->records;

		i=0;
		spin_lock_irqsave(&dev->lock, flags);
		list_for_each_entry(ucontext, &dev->ucontext_head, list) {
			records[i].base.obj_num       = ucontext->ucontext_num;
			records[i].base.creation_time = ucontext->creation_time;
			records[i].pid  = ucontext->pid;
			records[i].tgid = ucontext->tgid;
			memcpy(records[i].comm, ucontext->comm, sizeof(ucontext->comm));
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		
		control->count = i;
		control->record_size = sizeof(struct pib_ucontext_record);
		break;
	}

	case PIB_DEBUGFS_PD: {
		struct pib_pd *pd;
		struct pib_pd_record *records;

		control = vzalloc(sizeof(struct pib_record_control) +
				  dev->nr_pd * sizeof(struct pib_pd_record));
		if (!control)
			return -ENOMEM;

		records  = (struct pib_pd_record *)control->records;

		i=0;
		spin_lock_irqsave(&dev->lock, flags);
		list_for_each_entry(pd, &dev->pd_head, list) {
			records[i].base.obj_num       = pd->pd_num;
			records[i].base.creation_time = pd->creation_time;
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		
		control->count = i;
		control->record_size = sizeof(struct pib_pd_record);
		break;
	}

	case PIB_DEBUGFS_MR: {
		struct pib_mr *mr;
		struct pib_mr_record *records;

		control = vzalloc(sizeof(struct pib_record_control) +
				  dev->nr_ucontext * sizeof(struct pib_mr_record));
		if (!control)
			return -ENOMEM;

		records  = (struct pib_mr_record *)control->records;

		i=0;
		spin_lock_irqsave(&dev->lock, flags);
		list_for_each_entry(mr, &dev->mr_head, list) {
			records[i].base.obj_num       = mr->mr_num;
			records[i].base.creation_time = mr->creation_time;
			records[i].pd_num	      = to_ppd(mr->ib_mr.pd)->pd_num,
			records[i].start	      = mr->start;
			records[i].length             = mr->length;
			records[i].lkey	 	      = mr->ib_mr.lkey;
			records[i].rkey     	      = mr->ib_mr.rkey;
			records[i].access_flags       = mr->access_flags;
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		
		control->count = i;
		control->record_size = sizeof(struct pib_mr_record);
		break;
	}

	case PIB_DEBUGFS_SRQ: {
		struct pib_srq *srq;
		struct pib_srq_record *records;

		control = vzalloc(sizeof(struct pib_record_control) +
				  dev->nr_ucontext * sizeof(struct pib_srq_record));
		if (!control)
			return -ENOMEM;

		records  = (struct pib_srq_record *)control->records;

		i=0;
		spin_lock_irqsave(&dev->lock, flags);
		list_for_each_entry(srq, &dev->srq_head, list) {
			records[i].base.obj_num       = srq->srq_num;
			records[i].base.creation_time = srq->creation_time;
			records[i].pd_num	      = to_ppd(srq->ib_srq.pd)->pd_num;
			records[i].state              = srq->state;
			records[i].max_wqe            = srq->ib_srq_attr.max_wr;
			records[i].nr_wqe             = srq->nr_recv_wqe;
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		
		control->count = i;
		control->record_size = sizeof(struct pib_srq_record);
		break;
	}

	case PIB_DEBUGFS_CQ: {
		struct pib_cq *cq;
		struct pib_cq_record *records;

		control = vzalloc(sizeof(struct pib_record_control) +
				  dev->nr_ucontext * sizeof(struct pib_cq_record));
		if (!control)
			return -ENOMEM;

		records  = (struct pib_cq_record *)control->records;

		i=0;
		spin_lock_irqsave(&dev->lock, flags);
		list_for_each_entry(cq, &dev->cq_head, list) {
			records[i].base.obj_num       = cq->cq_num;
			records[i].base.creation_time = cq->creation_time;
			i++;
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		
		control->count = i;
		control->record_size = sizeof(struct pib_cq_record);
		break;
	}

	default:
		BUG();
	}

	control->dev   = dev;
	control->type  = entry->type;

	ret = seq_open(file, &pib_debugfs_seq_ops);
	if (ret)
		goto err_seq_open;

	seq = file->private_data;
	seq->private = control;

	return 0;

err_seq_open:
	vfree(control);

	return ret;
}


static int pib_debugfs_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq;

	seq = file->private_data;
	vfree(seq->private);

	return seq_release(inode, file);
}


static const struct file_operations pib_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = pib_debugfs_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = pib_debugfs_release,
};


/******************************************************************************/
/*                                                                            */
/******************************************************************************/

int pib_register_debugfs(void)
{
	int i, j;

	pib_debugfs_root = debugfs_create_dir("pib", NULL);
	if (!pib_debugfs_root) {
		pr_err("pib: failed to create debugfs \"pib/\"\n");
		return -ENOMEM;
	}

	for (i=0 ; i<pib_phys_port_cnt ; i++)
		if (register_dev(pib_debugfs_root, pib_devs[i]))
			goto err_register_dev;

	return 0;

err_register_dev:
	for (j=0 ; j<i ; j++)
		unregister_dev(pib_devs[j]);

	debugfs_remove(pib_debugfs_root);
	pib_debugfs_root = NULL;

	return -ENOMEM;
}


void pib_unregister_debugfs(void)
{
	int i;

	if (!pib_debugfs_root)
		return;

	for (i=0 ; i<pib_phys_port_cnt ; i++) {
		BUG_ON(!pib_devs[i]);
		unregister_dev(pib_devs[i]);
	}

	debugfs_remove(pib_debugfs_root);
	pib_debugfs_root = NULL;
}


static int register_dev(struct dentry *root, struct pib_dev *dev)
{
	int i;

	dev->debugfs.dir = debugfs_create_dir(dev->ib_dev.name, root);
	if (!dev->debugfs.dir) {
		pr_err("pib: failed to create debugfs \"pib/%s/\"\n", dev->ib_dev.name);
		goto err;
	}

	for (i=0 ; i<PIB_DEBUGFS_LAST ; i++) {
		struct dentry *dentry;
		dentry = debugfs_create_file(debug_file_symbols[i], S_IFREG | S_IRUGO,
					     dev->debugfs.dir,
					     &dev->debugfs.entries[i],
					     &pib_debugfs_fops);
		if (!dentry) {
			pr_err("pib: failed to create debugfs \"pib/%s/%s\"\n",
			       dev->ib_dev.name, debug_file_symbols[i]);
			goto err;
		}

		dev->debugfs.entries[i].dev    = dev;
		dev->debugfs.entries[i].dentry = dentry;
		dev->debugfs.entries[i].type   = i;
	}

	return 0;

err:
	unregister_dev(dev);

	return -ENOMEM;
}


static void unregister_dev(struct pib_dev *dev)
{
	int i;

	for (i=PIB_DEBUGFS_LAST-1 ; 0 <= i ; i--) {
		struct dentry *dentry;
		dentry = dev->debugfs.entries[i].dentry;
		dev->debugfs.entries[i].dentry = NULL;
		if (dentry)
			debugfs_remove(dentry);
	}

	if (dev->debugfs.dir) {
		debugfs_remove(dev->debugfs.dir);
		dev->debugfs.dir = NULL;
	}
}
