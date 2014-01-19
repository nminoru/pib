/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>

#include <rdma/ib_user_verbs.h>

#include "pib.h"


MODULE_AUTHOR("Minoru NAKAMURA");
MODULE_DESCRIPTION(PIB_DRIVER_DESCRIPTION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(PIB_DRIVER_VERSION);


struct kmem_cache *pib_ah_cachep;
struct kmem_cache *pib_mr_cachep;
struct kmem_cache *pib_qp_cachep;
struct kmem_cache *pib_cq_cachep;
struct kmem_cache *pib_srq_cachep;
struct kmem_cache *pib_send_wqe_cachep;
struct kmem_cache *pib_recv_wqe_cachep;
struct kmem_cache *pib_ack_cachep;
struct kmem_cache *pib_cqe_cachep;
struct kmem_cache *pib_mcast_link_cachep;


u64 hca_guid_base;
struct pib_dev *pib_devs[PIB_MAX_HCA];
struct pib_easy_sw  pib_easy_sw;

int pib_debug_level;
module_param_named(debug_level, pib_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0");

unsigned int pib_num_hca = 2;
module_param_named(num_hca, pib_num_hca, uint, S_IRUGO);
MODULE_PARM_DESC(num_hca, "Number of pib HCAs");

unsigned int pib_phys_port_cnt = 2;
module_param_named(phys_port_cnt, pib_phys_port_cnt, uint, S_IRUGO);
MODULE_PARM_DESC(phys_port_cnt, "Number of physical ports");


static struct class *dummy_parent_class; /* /sys/class/pib */
static struct device *dummy_parent_device;
static u64 dummy_parent_device_dma_mask = DMA_BIT_MASK(32);
static struct sockaddr **lid_table;


static int pib_query_device(struct ib_device *ibdev,
			    struct ib_device_attr *props)
{
	struct pib_dev *dev = to_pdev(ibdev);

	*props = dev->ib_dev_attr;
	
	return 0;
}


static int pib_query_port(struct ib_device *ibdev, u8 port_num,
			  struct ib_port_attr *props)
{
	struct pib_dev *dev = to_pdev(ibdev);

	if (port_num < 1 || ibdev->phys_port_cnt < port_num)
		return -EINVAL;

	*props = dev->ports[port_num - 1].ib_port_attr;
	
	return 0;
}


static enum rdma_link_layer
pib_get_link_layer(struct ib_device *device, u8 port_num)
{
	return IB_LINK_LAYER_INFINIBAND;
}


static int pib_query_gid(struct ib_device *ibdev, u8 port_num, int index,
			 union ib_gid *gid)
{
	struct pib_dev *dev;

	if (!ibdev)
		return -EINVAL;

	dev = to_pdev(ibdev);

	if (port_num < 1 || ibdev->phys_port_cnt < port_num)
		return -EINVAL;

	if (index < 0 || PIB_GID_PER_PORT < index)
		return -EINVAL;
	
	if (!gid)
		return -ENOMEM;

	*gid = dev->ports[port_num - 1].gid[index];

	return 0;
}


static int pib_query_pkey(struct ib_device *ibdev, u8 port_num, u16 index, u16 *pkey)
{
	struct pib_dev *dev;

	dev = to_pdev(ibdev);

	if (index < PIB_PKEY_PER_BLOCK)
		*pkey = be16_to_cpu(dev->ports[port_num - 1].pkey_table[index]);
	else
		*pkey = 0;

	return 0;
}


static int pib_modify_device(struct ib_device *ibdev, int mask,
			     struct ib_device_modify *props)
{
	struct pib_dev *dev;
	unsigned long flags;

	pib_debug("pib: pib_modify_device: mask=%x\n", mask);

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID|IB_DEVICE_MODIFY_NODE_DESC))
		return -EOPNOTSUPP;

	dev = to_pdev(ibdev);

	spin_lock_irqsave(&dev->lock, flags);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC)
		/* @todo ポート毎の処理 (c.f. qib_node_desc_chg) */
		memcpy(dev->ib_dev.node_desc, props->node_desc, sizeof(props->node_desc));

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		/* @todo ポート毎の処理 (c.f. qib_sys_guid_chg) */
		dev->ib_dev_attr.sys_image_guid = props->sys_image_guid;

	spin_unlock_irqrestore(&dev->lock, flags);

	return 0;
}


static int pib_modify_port(struct ib_device *ibdev, u8 port_num, int mask,
			      struct ib_port_modify *props)
{
	struct pib_dev *dev;
	unsigned long flags;

	pib_debug("pib: pib_modify_port: port=%u, mask=%x,%x,%x\n",
		  port_num, mask, props->set_port_cap_mask, props->clr_port_cap_mask);

	if (mask & ~(IB_PORT_SHUTDOWN|IB_PORT_INIT_TYPE|IB_PORT_RESET_QKEY_CNTR))
		return -EOPNOTSUPP;

	dev = to_pdev(ibdev);

	spin_lock_irqsave(&dev->lock, flags);

	if (mask & IB_PORT_INIT_TYPE)
		pr_err("pib: pib_modify_port: init type\n");

	if (mask & IB_PORT_SHUTDOWN)
		pr_err("pib: pib_modify_port: port shutdown\n");

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		pr_err("pib: pib_modify_port: port reset qkey control\n");

	dev->ports[port_num - 1].ib_port_attr.port_cap_flags |= props->set_port_cap_mask;
	dev->ports[port_num - 1].ib_port_attr.port_cap_flags &= ~props->clr_port_cap_mask;

	/* @todo port_cap_flags 変化を伝達 */

	spin_unlock_irqrestore(&dev->lock, flags);

	return 0;
}


static int pib_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	pib_debug("pib: pib_mmap\n");

	return -EINVAL;
}


static ssize_t show_behavior(struct device *device, struct device_attribute *attr,
			     char *buf)
{
	struct pib_dev *dev =
		container_of(device, struct pib_dev, ib_dev.dev);

	return sprintf(buf, "0x%x\n", dev->behavior);
}


static ssize_t store_behavior(struct device *device, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	unsigned int behavior;
	ssize_t result;	
	struct pib_dev *dev =
		container_of(device, struct pib_dev, ib_dev.dev);

	result = sscanf(buf, "0x%x", &behavior);
	if (result != 1)
		return -EINVAL;

	dev->behavior = behavior;
	
	return count;
}


static ssize_t show_local_ca_ack_delay(struct device *device, struct device_attribute *attr,
				       char *buf)
{
	struct pib_dev *dev =
		container_of(device, struct pib_dev, ib_dev.dev);

	return sprintf(buf, "%u\n", dev->ib_dev_attr.local_ca_ack_delay);
}


static ssize_t store_local_ca_ack_delay(struct device *device, struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int local_ca_ack_delay;
	ssize_t result;	
	struct pib_dev *dev =
		container_of(device, struct pib_dev, ib_dev.dev);

	result = sscanf(buf, "%u", &local_ca_ack_delay);
	if (result != 1)
		return -EINVAL;

	if ((local_ca_ack_delay < 1) || (31 < local_ca_ack_delay))
		return -EINVAL;

	if (local_ca_ack_delay < pib_get_local_ca_ack_delay())
		local_ca_ack_delay = pib_get_local_ca_ack_delay();

	dev->ib_dev_attr.local_ca_ack_delay = (u8)local_ca_ack_delay;

	return count;
}


#ifdef PIB_HACK_IMM_DATA_LKEY
static ssize_t show_imm_data_lkey(struct device *device, struct device_attribute *attr,
			     char *buf)
{
	struct pib_dev *dev =
		container_of(device, struct pib_dev, ib_dev.dev);

	return sprintf(buf, "0x%08x\n", dev->imm_data_lkey);
}
#endif


static DEVICE_ATTR(behavior,		S_IRUGO|S_IWUGO, show_behavior,  store_behavior);
static DEVICE_ATTR(local_ca_ack_delay,	S_IRUGO|S_IWUGO, show_local_ca_ack_delay, store_local_ca_ack_delay);

#ifdef PIB_HACK_IMM_DATA_LKEY
static DEVICE_ATTR(imm_data_lkey, S_IRUGO, show_imm_data_lkey, NULL);
#endif


static struct device_attribute *pib_class_attributes[] = {
	&dev_attr_behavior,
	&dev_attr_local_ca_ack_delay,
#ifdef PIB_HACK_IMM_DATA_LKEY
	&dev_attr_imm_data_lkey,
#endif
};


static struct pib_dev *pib_dev_add(struct device *dma_device, int ib_dev_id)
{
	int i, j;
	struct pib_dev *dev;
	struct ib_device_attr ib_dev_attr = {
		.fw_ver              = PIB_DRIVER_FW_VERSION,
		.sys_image_guid      = cpu_to_be64(hca_guid_base | 0x0200ULL),
		.max_mr_size         = 0xffffffffffffffffULL,
		.page_size_cap       = 0xfffffe00UL, /* @todo */
		.vendor_id           = 1U,
		.vendor_part_id      = 1U,
		.hw_ver              = 0U,
		.max_qp              = 131008,
		.max_qp_wr           = 16351,
		.device_cap_flags    = 0,

		.max_sge             = PIB_MAX_SGE,
		.max_sge_rd          =       8,
		.max_cq              =   65408,
		.max_cqe             = 4194303,
		.max_mr              =  524272,
		.max_pd              =   32764,
		.max_qp_rd_atom      = PIB_MAX_RD_ATOM,
		.max_ee_rd_atom      =       0,
		.max_res_rd_atom     = 2096128,
		.max_qp_init_rd_atom =     128,
		.max_ee_init_rd_atom =       0,
		.atomic_cap          = IB_ATOMIC_GLOB,
		.masked_atomic_cap   = IB_ATOMIC_GLOB,
		.max_ee              =       0,
		.max_rdd             =       0,
		.max_mw              =       0,
		.max_raw_ipv6_qp     =       0,
		.max_raw_ethy_qp     =       0,
		.max_mcast_grp       =    8192,
		.max_mcast_qp_attach = PIB_MCAST_QP_ATTACH,
		.max_total_mcast_qp_attach = 2031616,
		.max_ah              =   65536,
		.max_fmr             =       0, 
		.max_map_per_fmr     =       0,
		.max_srq             =   65472,
		.max_srq_wr          =   16383,
		.max_srq_sge         = PIB_MAX_SGE -1, /* for Mellanox HCA simulation */
		.max_fast_reg_page_list_len = 0,
		.max_pkeys           =     125,
		.local_ca_ack_delay  = pib_get_local_ca_ack_delay(),
	};

	dev = (struct pib_dev *)ib_alloc_device(sizeof *dev);
	if (!dev) {
		pr_err("pib: Device struct alloc failed\n");
		return NULL;
	}

	dev->ib_dev_id			= ib_dev_id;

	strlcpy(dev->ib_dev.name, "pib_%d", IB_DEVICE_NAME_MAX);

	dev->ib_dev.owner		= THIS_MODULE;
	dev->ib_dev.node_type		= RDMA_NODE_IB_CA;
	dev->ib_dev.node_guid		= cpu_to_be64(hca_guid_base | ((3 + ib_dev_id) << 8) | 0);
	dev->ib_dev.local_dma_lkey	= 0;
	dev->ib_dev.phys_port_cnt	= pib_phys_port_cnt;
	dev->ib_dev.num_comp_vectors	= num_possible_cpus();
	dev->ib_dev.uverbs_abi_ver	= PIB_UVERBS_ABI_VERSION;

	memcpy(dev->ib_dev.node_desc,
	       PIB_DRIVER_DESCRIPTION,
	       sizeof(PIB_DRIVER_DESCRIPTION));

	dev->ib_dev.uverbs_cmd_mask	=
		(1ULL << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ULL << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ULL << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ULL << IB_USER_VERBS_CMD_CREATE_AH)           |
		(1ULL << IB_USER_VERBS_CMD_MODIFY_AH)           |
		(1ULL << IB_USER_VERBS_CMD_QUERY_AH)            |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_AH)          |		
		(1ULL << IB_USER_VERBS_CMD_REG_MR)		|
		/* (1ULL << IB_USER_VERBS_CMD_REG_SMR)	           | */
		/* (1ULL << IB_USER_VERBS_CMD_REREG_MR)	           | */
		/* (1ULL << IB_USER_VERBS_CMD_QUERY_MR)	           | */
		(1ULL << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ULL << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ULL << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ULL << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ULL << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ULL << IB_USER_VERBS_CMD_POLL_CQ)             |
		(1ULL << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ)       |
		(1ULL << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ULL << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ULL << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ULL << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ULL << IB_USER_VERBS_CMD_POST_SEND)		|
		(1ULL << IB_USER_VERBS_CMD_POST_RECV)		|
		(1ULL << IB_USER_VERBS_CMD_ATTACH_MCAST)        |
		(1ULL << IB_USER_VERBS_CMD_DETACH_MCAST)        |
		(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_POST_SRQ_RECV);

	dev->ib_dev.query_device	= pib_query_device;
	dev->ib_dev.query_port		= pib_query_port;
	dev->ib_dev.get_link_layer	= pib_get_link_layer;
	dev->ib_dev.query_gid		= pib_query_gid;
	dev->ib_dev.query_pkey		= pib_query_pkey;
	dev->ib_dev.modify_device	= pib_modify_device;
	dev->ib_dev.modify_port		= pib_modify_port;
	dev->ib_dev.alloc_ucontext	= pib_alloc_ucontext;
	dev->ib_dev.dealloc_ucontext	= pib_dealloc_ucontext;
	dev->ib_dev.mmap		= pib_mmap;
	dev->ib_dev.alloc_pd		= pib_alloc_pd;
	dev->ib_dev.dealloc_pd		= pib_dealloc_pd;
	dev->ib_dev.create_ah		= pib_create_ah;
	dev->ib_dev.modify_ah		= pib_modify_ah;
	dev->ib_dev.query_ah		= pib_query_ah;
	dev->ib_dev.destroy_ah		= pib_destroy_ah;
	dev->ib_dev.create_srq		= pib_create_srq;
	dev->ib_dev.modify_srq		= pib_modify_srq;
	dev->ib_dev.query_srq		= pib_query_srq;
	dev->ib_dev.destroy_srq		= pib_destroy_srq;
	dev->ib_dev.post_srq_recv	= pib_post_srq_recv;
	dev->ib_dev.create_qp		= pib_create_qp;
	dev->ib_dev.modify_qp		= pib_modify_qp;
	dev->ib_dev.query_qp		= pib_query_qp;
	dev->ib_dev.destroy_qp		= pib_destroy_qp;
	dev->ib_dev.post_send		= pib_post_send;
	dev->ib_dev.post_recv		= pib_post_recv;
	dev->ib_dev.create_cq		= pib_create_cq;
	dev->ib_dev.modify_cq		= pib_modify_cq;
	dev->ib_dev.resize_cq		= pib_resize_cq;
	dev->ib_dev.destroy_cq		= pib_destroy_cq;
	dev->ib_dev.poll_cq		= pib_poll_cq;
	dev->ib_dev.req_notify_cq	= pib_req_notify_cq;
	dev->ib_dev.get_dma_mr		= pib_get_dma_mr;
	dev->ib_dev.reg_user_mr		= pib_reg_user_mr;
	dev->ib_dev.dereg_mr		= pib_dereg_mr;
	dev->ib_dev.alloc_fast_reg_mr 	= pib_alloc_fast_reg_mr;
	dev->ib_dev.alloc_fast_reg_page_list = pib_alloc_fast_reg_page_list;
	dev->ib_dev.free_fast_reg_page_list  = pib_free_fast_reg_page_list;
	dev->ib_dev.attach_mcast	= pib_attach_mcast;
	dev->ib_dev.detach_mcast	= pib_detach_mcast;
	dev->ib_dev.process_mad		= pib_process_mad;
	dev->ib_dev.dma_ops		= &pib_dma_mapping_ops;

	spin_lock_init(&dev->lock);

	dev->last_qp_num		= pib_random() & PIB_QPN_MASK;
	dev->qp_table			= RB_ROOT;

	INIT_LIST_HEAD(&dev->ucontext_head);
	INIT_LIST_HEAD(&dev->cq_head);

	spin_lock_init(&dev->schedule.lock);
	dev->schedule.wakeup_time	= jiffies;
	dev->schedule.rb_root		= RB_ROOT;

	dev->ib_dev_attr		= ib_dev_attr;

	dev->mcast_table		= vzalloc(sizeof(struct list_head) * (PIB_MAX_LID - PIB_MCAST_LID_BASE));
	if (!dev->mcast_table)
		goto err_mcast_table;

	for (i=0 ; i<PIB_MAX_LID - PIB_MCAST_LID_BASE ; i++)
		INIT_LIST_HEAD(&dev->mcast_table[i]);

	dev->ports			= vzalloc(sizeof(struct sockaddr*) * dev->ib_dev.phys_port_cnt);
	if (!dev->ports)
		goto err_ports;

	for (i=0 ; i < dev->ib_dev.phys_port_cnt ; i++) {
		struct ib_port_attr ib_port_attr = {
			/* .state           = IB_PORT_DOWN, */
			.state           = IB_PORT_INIT,
			.max_mtu         = IB_MTU_4096,
			.active_mtu      = IB_MTU_256,
			.gid_tbl_len     = PIB_GID_PER_PORT,
			.port_cap_flags  = PIB_PORT_CAP_FLAGS,
			.max_msg_sz      = PIB_MAX_PAYLOAD_LEN,
			.bad_pkey_cntr   = 0U,
			.qkey_viol_cntr  = 128,
			.pkey_tbl_len    = PIB_PKEY_TABLE_LEN,
			.lid             = 0U,
			.sm_lid          = 0U,
			.lmc             = 0U,
			.max_vl_num      = 4U,
			.sm_sl           = 0U,
			.subnet_timeout  = 0U,
			.init_type_reply = 0U,
			.active_width    = IB_WIDTH_12X,
			.active_speed    = IB_SPEED_QDR,
			.phys_state      = PIB_PHYS_PORT_POLLING,
		};

		dev->ports[i].port_num	= i + 1;
		dev->ports[i].ib_port_attr = ib_port_attr;

		if (lid_table != NULL) {
			dev->ports[i].lid_table = lid_table;
		} else {
			dev->ports[i].lid_table = vzalloc(sizeof(struct sockaddr*) * PIB_MAX_LID);
			if (!dev->ports[i].lid_table)
				goto err_ld_table;
		}

		/*
		 * @see IBA Spec. Vol.1 4.1.1
		 */
		dev->ports[i].gid[0].global.subnet_prefix =
			/* default GID prefix */
			cpu_to_be64(0xFE80000000000000ULL);
		dev->ports[i].gid[0].global.interface_id  =
			cpu_to_be64(hca_guid_base | ((3 + ib_dev_id) << 8) | (i + 1));

		dev->ports[i].link_width_enabled = PIB_LINK_WIDTH_SUPPORTED;
		dev->ports[i].link_speed_enabled = PIB_LINK_SPEED_SUPPORTED;

		for (j=0 ; j < PIB_PKEY_PER_BLOCK ; j++)
			dev->ports[i].pkey_table[j] = cpu_to_be16(IB_DEFAULT_PKEY_FULL);
	}

	dev->behavior		= 0U;
#ifdef PIB_HACK_IMM_DATA_LKEY
	dev->imm_data_lkey	= PIB_IMM_DATA_LKEY;
#endif

	dev->ib_dev.dma_device = dma_device;

	if (ib_register_device(&dev->ib_dev, NULL))
		goto err_register_ibdev;

	if (pib_create_kthread(dev))
		goto err_create_kthread;

	for (i = 0; i < ARRAY_SIZE(pib_class_attributes); i++)
		if (device_create_file(&dev->ib_dev.dev, pib_class_attributes[i]))
			goto err_create_file;

	pr_info("pib: add HCA (dev_id=%d, ports=%u)\n",
		dev->ib_dev_id, dev->ib_dev.phys_port_cnt);

	return dev;

err_create_file:
	for (j = i - 1; j >= 0 ; j--)
		device_remove_file(&dev->ib_dev.dev, pib_class_attributes[j]);

	pib_release_kthread(dev);

err_create_kthread:
	ib_unregister_device(&dev->ib_dev);	

err_register_ibdev:

err_ld_table:
	if (lid_table == NULL)
		for (i = dev->ib_dev.phys_port_cnt - 1 ; 0 <= i ; i--)
			if (dev->ports[i].lid_table)
				vfree(dev->ports[i].lid_table);

	vfree(dev->ports);
err_ports:

	vfree(dev->mcast_table);
err_mcast_table:

	ib_dealloc_device(&dev->ib_dev);

	return NULL;
}


static void pib_dev_remove(struct pib_dev *dev)
{
	int i;

	pr_info("pib: remove HCA (dev_id=%d)\n", dev->ib_dev_id);

	ib_unregister_device(&dev->ib_dev);

	pib_release_kthread(dev);

	if (lid_table == NULL)
		for (i= dev->ib_dev.phys_port_cnt - 1 ; 0 <= i ; i--)
			if (dev->ports[i].lid_table)
				vfree(dev->ports[i].lid_table);

	vfree(dev->ports);
	vfree(dev->mcast_table);

	ib_dealloc_device(&dev->ib_dev);
}


static int pib_kmem_cache_create(void)
{
	pib_ah_cachep = kmem_cache_create("pib_ah",
					  sizeof(struct pib_ah), 0,
					  0, NULL);

	if (!pib_ah_cachep)
		return -1;

	pib_mr_cachep = kmem_cache_create("pib_mr",
					  sizeof(struct pib_mr), 0,
					  0, NULL);

	if (!pib_mr_cachep)
		return -1;
	
	pib_qp_cachep = kmem_cache_create("pib_qp",
					  sizeof(struct pib_qp), 0,
					  0, NULL);
	
	if (!pib_qp_cachep)
		return -1;

	pib_cq_cachep = kmem_cache_create("pib_cq",
					  sizeof(struct pib_cq), 0,
					  0, NULL);
	
	if (!pib_cq_cachep)
		return -1;

	pib_srq_cachep = kmem_cache_create("pib_srq",
					   sizeof(struct pib_srq), 0,
					   0, NULL);

	if (!pib_srq_cachep)
		return -1;

	pib_send_wqe_cachep = kmem_cache_create("pib_send_wqe",
						sizeof(struct pib_send_wqe), 0,
						0, NULL);

	if (!pib_send_wqe_cachep)
		return -1;

	pib_recv_wqe_cachep = kmem_cache_create("pib_recv_wqe",
						sizeof(struct pib_recv_wqe) ,0,
						0, NULL);

	if (!pib_recv_wqe_cachep)
		return -1;

	pib_ack_cachep = kmem_cache_create("pib_ack",
					   sizeof(struct pib_ack) ,0,
					   0, NULL);
	
	if (!pib_ack_cachep)
		return -1;

	pib_cqe_cachep = kmem_cache_create("pib_cqe",
					   sizeof(struct pib_cqe), 0,
					   0, NULL);

	if (!pib_cqe_cachep)
		return -1;

	pib_mcast_link_cachep = kmem_cache_create("pib_mcast_link",
					   sizeof(struct pib_mcast_link), 0,
					   0, NULL);

	if (!pib_mcast_link_cachep)
		return -1;

	return 0;
}


static void pib_kmem_cache_destroy(void)
{
	if (pib_ah_cachep)
		kmem_cache_destroy(pib_ah_cachep);

	if (pib_mr_cachep)
		kmem_cache_destroy(pib_mr_cachep);

	if (pib_qp_cachep)
		kmem_cache_destroy(pib_qp_cachep);

	if (pib_cq_cachep)
		kmem_cache_destroy(pib_cq_cachep);

	if (pib_srq_cachep)
		kmem_cache_destroy(pib_srq_cachep);

	if (pib_send_wqe_cachep)
		kmem_cache_destroy(pib_send_wqe_cachep);

	if (pib_recv_wqe_cachep)
		kmem_cache_destroy(pib_recv_wqe_cachep);

	if (pib_ack_cachep)
		kmem_cache_destroy(pib_ack_cachep);

	if (pib_cqe_cachep)
		kmem_cache_destroy(pib_cqe_cachep);

	if (pib_mcast_link_cachep)
		kmem_cache_destroy(pib_mcast_link_cachep);

	pib_ah_cachep = NULL;
	pib_mr_cachep = NULL;
	pib_qp_cachep = NULL;
	pib_cq_cachep = NULL;
	pib_srq_cachep = NULL;
	pib_send_wqe_cachep = NULL;
	pib_recv_wqe_cachep = NULL;
	pib_ack_cachep = NULL;
	pib_cqe_cachep = NULL;
	pib_mcast_link_cachep = NULL;
}


/*
 *  pib's 64-bits GUID is derived from the 48-bits MAC address of the first
 *  effective Ethernet NIC on this host.
 */
static void get_hca_guid_base(void)
{
	int i;
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		if (dev->flags & IFF_LOOPBACK)
			continue;

		if (!dev->dev_addr)
			continue;

		for (i=0 ; i<ETH_ALEN ; i++) {
			hca_guid_base |= (u8)dev->dev_addr[i];
			hca_guid_base <<= 8;
		}
		
		hca_guid_base <<= (sizeof(hca_guid_base) - ETH_ALEN - 1) * 8;
		break;
	}
	rtnl_unlock();

	if (hca_guid_base == 0)
		hca_guid_base = 0xCafeBabe0000ULL;
}


static int __init pib_init(void)
{
	int i, j, err = 0;

	pr_info("pib: " PIB_DRIVER_DESCRIPTION " v" PIB_DRIVER_VERSION "\n");

	if ((pib_num_hca < 1) || (PIB_MAX_HCA < pib_num_hca)) {
		pr_err("pib: pib_num_hca: %u\n", pib_num_hca);
		return -EINVAL;
	}

	if ((pib_phys_port_cnt < 1) || (PIB_MAX_PORTS < pib_phys_port_cnt)) {
		pr_err("pib: phys_port_cnt: %u\n", pib_phys_port_cnt);
		return -EINVAL;
	}

	dummy_parent_class = class_create(THIS_MODULE, "pib");
	if (IS_ERR(dummy_parent_class)) {
		err = PTR_ERR(dummy_parent_class);
		goto err_class_create;
	}

	dummy_parent_device = device_create(dummy_parent_class, NULL, MKDEV(0, 0), NULL, "pib_root");
	if (IS_ERR(dummy_parent_device)) {
		err = PTR_ERR(dummy_parent_device);
		goto err_device_create;
	}

	dummy_parent_device->dma_mask = &dummy_parent_device_dma_mask;

	get_hca_guid_base();

#ifdef PIB_USE_EASY_SWITCH
	lid_table = vzalloc(sizeof(struct sockaddr*) * PIB_MAX_LID);
	if (!lid_table)
		goto err_alloc_lid_table;
#endif

	if (pib_kmem_cache_create()) {
		pib_kmem_cache_destroy();
		err = -ENOMEM;
		goto err_kmem_cache_destroy;
	}

	if (pib_create_switch(&pib_easy_sw))
		goto err_create_switch;

	for (i=0 ; i<pib_num_hca ; i++) {
		pib_devs[i] = pib_dev_add(dummy_parent_device, i);
		if (!pib_devs[i]) {
			err = -1;
			goto err_ib_add;
		}
	}

	return 0;

err_ib_add:
	for (j=i - 1 ; 0 <= j ; j--)
		if (pib_devs[j])
			pib_dev_remove(pib_devs[j]);

	pib_release_switch(&pib_easy_sw);
err_create_switch:

	pib_kmem_cache_destroy();
err_kmem_cache_destroy:

#ifdef PIB_USE_EASY_SWITCH
	vfree(lid_table);
err_alloc_lid_table:
#endif

	device_unregister(dummy_parent_device);
	dummy_parent_device = NULL;
err_device_create:

	class_destroy(dummy_parent_class);
	dummy_parent_class = NULL;
err_class_create:

	return err;
}


static void __exit pib_cleanup(void)
{
	int i;

	pr_info("pib: unload\n");

	for (i = pib_num_hca - 1 ; 0 <= i ; i--)
		if (pib_devs[i])
			pib_dev_remove(pib_devs[i]);

	pib_release_switch(&pib_easy_sw);

	pib_kmem_cache_destroy();

#ifdef PIB_USE_EASY_SWITCH
	vfree(lid_table);
#endif

	if (dummy_parent_device) {
		device_unregister(dummy_parent_device);
		dummy_parent_device = NULL;
	}

	if (dummy_parent_class) {
		class_destroy(dummy_parent_class);
		dummy_parent_class = NULL;
	}
}


module_init(pib_init);
module_exit(pib_cleanup);
