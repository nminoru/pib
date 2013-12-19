/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
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
MODULE_DESCRIPTION("Pseudo InfiniBand HCA driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(PIB_DRIVER_VERSION);


struct kmem_cache *pib_ib_ah_cachep;
struct kmem_cache *pib_ib_mr_cachep;
struct kmem_cache *pib_ib_qp_cachep;
struct kmem_cache *pib_ib_cq_cachep;
struct kmem_cache *pib_ib_srq_cachep;
struct kmem_cache *pib_ib_send_wqe_cachep;
struct kmem_cache *pib_ib_recv_wqe_cachep;
struct kmem_cache *pib_ib_ack_cachep;
struct kmem_cache *pib_ib_cqe_cachep;


static u64 hca_guid_base;
static struct class *dummy_parent_class; /* /sys/class/pib */
static struct device *dummy_parent_device;
static struct pib_ib_dev *pib_ib_devs[PIB_IB_MAX_HCA];

static unsigned int pib_num_hca = 1;
module_param_named(num_hca, pib_num_hca, uint, S_IRUGO);
MODULE_PARM_DESC(num_hca, "Number of pib HCAs");

static unsigned int pib_phys_port_cnt = 2;
module_param_named(phys_port_cnt, pib_phys_port_cnt, uint, S_IRUGO);
MODULE_PARM_DESC(phys_port_cnt, "Number of physical ports");


static int pib_ib_query_device(struct ib_device *ibdev,
			       struct ib_device_attr *props)
{
	struct pib_ib_dev *dev = to_pdev(ibdev);

	*props = dev->ib_dev_attr;
	
	return 0;
}


static int pib_ib_query_port(struct ib_device *ibdev, u8 port_num,
			     struct ib_port_attr *props)
{
	struct pib_ib_dev *dev = to_pdev(ibdev);

	if (port_num < 1 || ibdev->phys_port_cnt < port_num)
		return -EINVAL;

	*props = dev->ports[port_num - 1].ib_port_attr;
	
	return 0;
}


static enum rdma_link_layer
pib_ib_get_link_layer(struct ib_device *device, u8 port_num)
{
	return IB_LINK_LAYER_INFINIBAND;
}


static int pib_ib_query_gid(struct ib_device *ibdev, u8 port_num, int index,
			    union ib_gid *gid)
{
	struct pib_ib_dev *dev;

	if (!ibdev)
		return -EINVAL;

	dev = to_pdev(ibdev);

	if (port_num < 1 || ibdev->phys_port_cnt < port_num)
		return -EINVAL;

	if (index < 0 || PIB_IB_GID_PER_PORT < index)
		return -EINVAL;
	
	if (!gid)
		return -ENOMEM;

	*gid = dev->ports[port_num - 1].gid[index];

	return 0;
}


static int pib_ib_query_pkey(struct ib_device *ibdev, u8 port_num, u16 index, u16 *pkey)
{
	/* @todo */
	*pkey = (index == 0) ? IB_DEFAULT_PKEY_FULL : 0;
	return 0;
}


static int pib_ib_modify_device(struct ib_device *ibdev, int mask,
				struct ib_device_modify *props)
{
	struct pib_ib_dev *dev;

	debug_printk("pib_ib_modify_device: mask=%x\n", mask);

	if (mask & ~(IB_DEVICE_MODIFY_SYS_IMAGE_GUID|IB_DEVICE_MODIFY_NODE_DESC))
		return -EOPNOTSUPP;

	dev = to_pdev(ibdev);

	down_write(&dev->rwsem);

	if (mask & IB_DEVICE_MODIFY_NODE_DESC)
		/* @todo ポート毎の処理 (c.f. qib_node_desc_chg) */
		memcpy(dev->ib_dev.node_desc, props->node_desc, sizeof(props->node_desc));

	if (mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID)
		/* @todo ポート毎の処理 (c.f. qib_sys_guid_chg) */
		dev->ib_dev_attr.sys_image_guid = props->sys_image_guid;

	up_write(&dev->rwsem);

	return 0;
}


static int pib_ib_modify_port(struct ib_device *ibdev, u8 port_num, int mask,
			      struct ib_port_modify *props)
{
	struct pib_ib_dev *dev;

	debug_printk("pib_ib_modify_port: port=%u, mask=%x,%x,%x\n", port_num, mask, props->set_port_cap_mask, props->clr_port_cap_mask);

	if (mask & ~(IB_PORT_SHUTDOWN|IB_PORT_INIT_TYPE|IB_PORT_RESET_QKEY_CNTR))
		return -EOPNOTSUPP;

	dev = to_pdev(ibdev);

	down_write(&dev->rwsem);

	if (mask & IB_PORT_INIT_TYPE)
		debug_printk("pib_ib_modify_port: init type\n");

	if (mask & IB_PORT_SHUTDOWN)
		debug_printk("pib_ib_modify_port: port shutdown\n");

	if (mask & IB_PORT_RESET_QKEY_CNTR)
		debug_printk("pib_ib_modify_port: port reset qkey control\n");

	dev->ports[port_num - 1].ib_port_attr.port_cap_flags |= props->set_port_cap_mask;
	dev->ports[port_num - 1].ib_port_attr.port_cap_flags &= ~props->clr_port_cap_mask;

	/* @todo port_cap_flags 変化を伝達 */

	up_write(&dev->rwsem);

	return 0;
}


static int pib_ib_mmap(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	debug_printk("pib_ib_mmap\n");
	return -EINVAL;
}


static ssize_t show_behavior(struct device *device, struct device_attribute *attr,
			     char *buf)
{
	struct pib_ib_dev *ibdev =
		container_of(device, struct pib_ib_dev, ib_dev.dev);

	return sprintf(buf, "%u\n", ibdev->behavior);
}


#ifdef PIB_HACK_IMM_DATA_LKEY
static ssize_t show_imm_data_lkey(struct device *device, struct device_attribute *attr,
			     char *buf)
{
	struct pib_ib_dev *ibdev =
		container_of(device, struct pib_ib_dev, ib_dev.dev);

	return sprintf(buf, "0x%08x\n", ibdev->imm_data_lkey);
}
#endif


static DEVICE_ATTR(behavior,      S_IRUGO, show_behavior,      NULL);
#ifdef PIB_HACK_IMM_DATA_LKEY
static DEVICE_ATTR(imm_data_lkey, S_IRUGO, show_imm_data_lkey, NULL);
#endif


static struct device_attribute *pib_class_attributes[] = {
	&dev_attr_behavior,
#ifdef PIB_HACK_IMM_DATA_LKEY
	&dev_attr_imm_data_lkey,
#endif
};


static struct pib_ib_dev *pib_ib_add(struct device *dma_device, int ib_dev_id)
{
	int i, j;
	struct pib_ib_dev *ibdev;
	struct ib_device_attr ib_dev_attr = {
		.fw_ver              = 0x00000000100010001ULL, /* 1.1.1 */
		.sys_image_guid      = cpu_to_be64(hca_guid_base | 0x10ULL),
		.max_mr_size         = 0xffffffffffffffffULL,
		.page_size_cap       = 0xfffffe00UL, /* @todo */
		.vendor_id           = 1U,
		.vendor_part_id      = 1U,
		.hw_ver              = 0U,
		.max_qp              = 131008,
		.max_qp_wr           = 16351,
		.device_cap_flags    = 0,

		.max_sge             = PIB_IB_MAX_SGE,
		.max_sge_rd          =       8,
		.max_cq              =   65408,
		.max_cqe             = 4194303,
		.max_mr              =  524272,
		.max_pd              =   32764,
		.max_qp_rd_atom      = PIB_IB_MAX_RD_ATOM,
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
		.max_mcast_qp_attach =     248,
		.max_total_mcast_qp_attach = 2031616,
		.max_ah              =   65536,
		.max_fmr             =       0, 
		.max_map_per_fmr     =       0,
		.max_srq             =   65472,
		.max_srq_wr          =   16383,
		.max_srq_sge         = PIB_IB_MAX_SGE -1, /* for Mellanox HCA simulation */
		.max_fast_reg_page_list_len = 0,
		.max_pkeys           =     125,
		.local_ca_ack_delay  =      15,
	};

	ibdev = (struct pib_ib_dev *)ib_alloc_device(sizeof *ibdev);
	if (!ibdev) {
		debug_printk(KERN_WARNING "Device struct alloc failed\n");
		return NULL;
	}

	ibdev->ib_dev_id		= ib_dev_id;

	strlcpy(ibdev->ib_dev.name, "pib_%d", IB_DEVICE_NAME_MAX);

	ibdev->ib_dev.owner		= THIS_MODULE;
	ibdev->ib_dev.node_type		= RDMA_NODE_IB_CA;
	ibdev->ib_dev.node_guid         = cpu_to_be64(hca_guid_base | 0x20ULL);
	ibdev->ib_dev.local_dma_lkey	= 0;
	ibdev->ib_dev.phys_port_cnt     = pib_phys_port_cnt;
	ibdev->ib_dev.num_comp_vectors	= num_possible_cpus();
	ibdev->ib_dev.uverbs_abi_ver    = PIB_IB_UVERBS_ABI_VERSION;

	ibdev->ib_dev.uverbs_cmd_mask	=
		(1ULL << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ULL << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ULL << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ULL << IB_USER_VERBS_CMD_CREATE_AH)           |
		/* (1ULL << IB_USER_VERBS_CMD_MODIFY_AH)           | */
		/* (1ULL << IB_USER_VERBS_CMD_QUERY_AH)            | */
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
		/* (1ULL << IB_USER_VERBS_CMD_ATTACH_MCAST)        | */
		/* (1ULL << IB_USER_VERBS_CMD_DETACH_MCAST)        | */
		(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
		(1ULL << IB_USER_VERBS_CMD_POST_SRQ_RECV);

	ibdev->ib_dev.query_device	= pib_ib_query_device;
	ibdev->ib_dev.query_port	= pib_ib_query_port;
	ibdev->ib_dev.get_link_layer	= pib_ib_get_link_layer;
	ibdev->ib_dev.query_gid		= pib_ib_query_gid;
	ibdev->ib_dev.query_pkey	= pib_ib_query_pkey;
	ibdev->ib_dev.modify_device	= pib_ib_modify_device;
	ibdev->ib_dev.modify_port	= pib_ib_modify_port;
	ibdev->ib_dev.alloc_ucontext	= pib_ib_alloc_ucontext;
	ibdev->ib_dev.dealloc_ucontext	= pib_ib_dealloc_ucontext;
	ibdev->ib_dev.mmap		= pib_ib_mmap;
	ibdev->ib_dev.alloc_pd		= pib_ib_alloc_pd;
	ibdev->ib_dev.dealloc_pd	= pib_ib_dealloc_pd;
	ibdev->ib_dev.create_ah		= pib_ib_create_ah;
	ibdev->ib_dev.destroy_ah	= pib_ib_destroy_ah;
	ibdev->ib_dev.create_srq	= pib_ib_create_srq;
	ibdev->ib_dev.modify_srq	= pib_ib_modify_srq;
	ibdev->ib_dev.query_srq		= pib_ib_query_srq;
	ibdev->ib_dev.destroy_srq	= pib_ib_destroy_srq;
	ibdev->ib_dev.post_srq_recv	= pib_ib_post_srq_recv;
	ibdev->ib_dev.create_qp		= pib_ib_create_qp;
	ibdev->ib_dev.modify_qp		= pib_ib_modify_qp;
	ibdev->ib_dev.query_qp		= pib_ib_query_qp;
	ibdev->ib_dev.destroy_qp	= pib_ib_destroy_qp;
	ibdev->ib_dev.post_send		= pib_ib_post_send;
	ibdev->ib_dev.post_recv		= pib_ib_post_recv;
	ibdev->ib_dev.create_cq		= pib_ib_create_cq;
	ibdev->ib_dev.modify_cq		= pib_ib_modify_cq;
	ibdev->ib_dev.resize_cq		= pib_ib_resize_cq;
	ibdev->ib_dev.destroy_cq	= pib_ib_destroy_cq;
	ibdev->ib_dev.poll_cq		= pib_ib_poll_cq;
	ibdev->ib_dev.req_notify_cq	= pib_ib_req_notify_cq;
	ibdev->ib_dev.get_dma_mr	= pib_ib_get_dma_mr;
	ibdev->ib_dev.reg_user_mr	= pib_ib_reg_user_mr;
	ibdev->ib_dev.dereg_mr		= pib_ib_dereg_mr;
	ibdev->ib_dev.alloc_fast_reg_mr = pib_ib_alloc_fast_reg_mr;
	ibdev->ib_dev.alloc_fast_reg_page_list = pib_ib_alloc_fast_reg_page_list;
	ibdev->ib_dev.free_fast_reg_page_list  = pib_ib_free_fast_reg_page_list;
#if 0
	ibdev->ib_dev.attach_mcast	= pib_ib_mcg_attach;
	ibdev->ib_dev.detach_mcast	= pib_ib_mcg_detach;
#endif
	ibdev->ib_dev.process_mad	= pib_ib_process_mad;
	ibdev->ib_dev.dma_ops		= &pib_dma_mapping_ops;

	spin_lock_init(&ibdev->lock);

	ibdev->last_qp_num		= pib_random() & PIB_IB_QPN_MASK;
	ibdev->qp_table			= RB_ROOT;

	INIT_LIST_HEAD(&ibdev->ucontext_head);
	INIT_LIST_HEAD(&ibdev->cq_head);

	spin_lock_init(&ibdev->schedule.lock);
	ibdev->schedule.wakeup_time	= jiffies;
	ibdev->schedule.rb_root		= RB_ROOT;

	init_rwsem(&ibdev->rwsem);

	ibdev->ib_dev_attr		= ib_dev_attr;

	for (i=0 ; i < ibdev->ib_dev.phys_port_cnt ; i++) {
		struct ib_port_attr ib_port_attr = {
			.state           = IB_PORT_DOWN,
			.max_mtu         = IB_MTU_4096,
			.active_mtu      = IB_MTU_4096,
			.gid_tbl_len     = PIB_IB_GID_PER_PORT,
			.port_cap_flags  = 0, /* 0x02514868, */
			.max_msg_sz      = 0x40000000,
			.bad_pkey_cntr   = 0U,
			.qkey_viol_cntr  = 128,
			.pkey_tbl_len    = 128,
			.lid             = i + 1,
			.sm_lid          = 0U,
			.lmc             = 0U,
			.max_vl_num      = 4U,
			.sm_sl           = 0U,
			.subnet_timeout  = 0U,
			.init_type_reply = 0U,
			.active_width    = IB_WIDTH_4X,
			.active_speed    = IB_SPEED_QDR,
			.phys_state      = PIB_IB_PHYS_PORT_POLLING,
		};

		ibdev->ports[i].port_num = i + 1;
		ibdev->ports[i].ib_port_attr = ib_port_attr;

		ibdev->ports[i].lid_table = vzalloc(sizeof(struct sockaddr*) * PIB_IB_MAX_LID);
		if (!ibdev->ports[i].lid_table)
			goto err_ld_table;

		/*
		 * @see IBA Spec. Vol.1 4.1.1
		 */
		ibdev->ports[i].gid[0].global.subnet_prefix =
			/* default GID prefix */
			cpu_to_be64(0xFE80000000000000ULL);
		ibdev->ports[i].gid[0].global.interface_id  =
			cpu_to_be64(hca_guid_base | ((ib_dev_id + 3) << 8) | i);
	}

	ibdev->behavior		= 0U;
#ifdef PIB_HACK_IMM_DATA_LKEY
	ibdev->imm_data_lkey	= PIB_IB_IMM_DATA_LKEY;
#endif

	ibdev->ib_dev.dma_device = dma_device;

	if (ib_register_device(&ibdev->ib_dev, NULL))
		goto err_register_ibdev;

	if (pib_create_kthread(ibdev))
		goto err_create_kthread;

	for (i = 0; i < ARRAY_SIZE(pib_class_attributes); i++)
		if (device_create_file(&ibdev->ib_dev.dev, pib_class_attributes[i]))
			goto err_create_file;

	return ibdev;

err_create_file:
	for (j = i - 1; j >= 0 ; j--)
		device_remove_file(&ibdev->ib_dev.dev, pib_class_attributes[j]);

	pib_release_kthread(ibdev);

err_create_kthread:
	ib_unregister_device(&ibdev->ib_dev);

err_register_ibdev:

err_ld_table:
	for (i= ibdev->ib_dev.phys_port_cnt - 1 ; 0 <= i ; i--)
		if (ibdev->ports[i].lid_table)
			vfree(ibdev->ports[i].lid_table);

	ib_dealloc_device(&ibdev->ib_dev);

	return NULL;
}


static void pib_ib_remove(struct pib_ib_dev *dev)
{
	int i;

	debug_printk("pib_ib_remove\n");

	ib_unregister_device(&dev->ib_dev);

	pib_release_kthread(dev);

	for (i= dev->ib_dev.phys_port_cnt - 1 ; 0 <= i ; i--)
		if (dev->ports[i].lid_table)
			vfree(dev->ports[i].lid_table);

	ib_dealloc_device(&dev->ib_dev);
}


static int pib_kmem_cache_create(void)
{
	pib_ib_ah_cachep = kmem_cache_create("pib_ib_ah",
					     sizeof(struct pib_ib_ah), 0,
					     0, NULL);

	if (!pib_ib_ah_cachep)
		return -1;

	pib_ib_mr_cachep = kmem_cache_create("pib_ib_mr",
					     sizeof(struct pib_ib_mr), 0,
					     0, NULL);

	if (!pib_ib_mr_cachep)
		return -1;

	pib_ib_qp_cachep = kmem_cache_create("pib_ib_qp",
					     sizeof(struct pib_ib_qp), 0,
					     0, NULL);

	if (!pib_ib_qp_cachep)
		return -1;

	pib_ib_cq_cachep = kmem_cache_create("pib_ib_cq",
					     sizeof(struct pib_ib_cq), 0,
					     0, NULL);

	if (!pib_ib_cq_cachep)
		return -1;

	pib_ib_srq_cachep = kmem_cache_create("pib_ib_srq",
					      sizeof(struct pib_ib_srq), 0,
					      0, NULL);

	if (!pib_ib_srq_cachep)
		return -1;

	pib_ib_send_wqe_cachep = kmem_cache_create("pib_ib_send_wqe",
						   sizeof(struct pib_ib_send_wqe), 0,
						   0, NULL);

	if (!pib_ib_send_wqe_cachep)
		return -1;

	pib_ib_recv_wqe_cachep = kmem_cache_create("pib_ib_recv_wqe",
						   sizeof(struct pib_ib_recv_wqe) ,0,
						   0, NULL);

	if (!pib_ib_recv_wqe_cachep)
		return -1;

	pib_ib_ack_cachep = kmem_cache_create("pib_ib_ack",
						   sizeof(struct pib_ib_ack) ,0,
						   0, NULL);

	if (!pib_ib_ack_cachep)
		return -1;

	pib_ib_cqe_cachep = kmem_cache_create("pib_ib_cqe",
					      sizeof(struct pib_ib_cqe), 0,
					      0, NULL);

	if (!pib_ib_cqe_cachep)
		return -1;

	return 0;
}


static void pib_kmem_cache_destroy(void)
{
	if (pib_ib_ah_cachep)
		kmem_cache_destroy(pib_ib_ah_cachep);

	if (pib_ib_mr_cachep)
		kmem_cache_destroy(pib_ib_mr_cachep);

	if (pib_ib_qp_cachep)
		kmem_cache_destroy(pib_ib_qp_cachep);

	if (pib_ib_cq_cachep)
		kmem_cache_destroy(pib_ib_cq_cachep);

	if (pib_ib_srq_cachep)
		kmem_cache_destroy(pib_ib_srq_cachep);

	if (pib_ib_send_wqe_cachep)
		kmem_cache_destroy(pib_ib_send_wqe_cachep);

	if (pib_ib_recv_wqe_cachep)
		kmem_cache_destroy(pib_ib_recv_wqe_cachep);

	if (pib_ib_ack_cachep)
		kmem_cache_destroy(pib_ib_ack_cachep);

	if (pib_ib_cqe_cachep)
		kmem_cache_destroy(pib_ib_cqe_cachep);

	pib_ib_ah_cachep = NULL;
	pib_ib_mr_cachep = NULL;
	pib_ib_qp_cachep = NULL;
	pib_ib_cq_cachep = NULL;
	pib_ib_srq_cachep = NULL;
	pib_ib_send_wqe_cachep = NULL;
	pib_ib_recv_wqe_cachep = NULL;
	pib_ib_ack_cachep = NULL;
	pib_ib_cqe_cachep = NULL;
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


static int __init pib_ib_init(void)
{
	int i, j, err = 0;

	if ((pib_num_hca < 1) || (PIB_IB_MAX_HCA < pib_num_hca)) {
		printk(KERN_ERR "pib_num_hca: %u\n", pib_num_hca);
		return -EINVAL;
	}

	if ((pib_phys_port_cnt < 1) || (PIB_IB_MAX_PORTS < pib_phys_port_cnt)) {
		printk(KERN_ERR "phys_port_cnt: %u\n", pib_phys_port_cnt);
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

	get_hca_guid_base();

	if (pib_kmem_cache_create()) {
		pib_kmem_cache_destroy();
		err = -ENOMEM;
		goto err_kmem_cache_destroy;
	}

	for (i=0 ; i<pib_num_hca ; i++) {
		pib_ib_devs[i] = pib_ib_add(dummy_parent_device, i);
		if (!pib_ib_devs[i]) {
			err = -1;
			goto err_ib_add;
		}
	}

	return 0;

err_ib_add:
	for (j=i - 1 ; 0 <= j ; j--)
		if (pib_ib_devs[j])
			pib_ib_remove(pib_ib_devs[j]);

	pib_kmem_cache_destroy();
err_kmem_cache_destroy:

	device_unregister(dummy_parent_device);
	dummy_parent_device = NULL;
err_device_create:

	class_destroy(dummy_parent_class);
	dummy_parent_class = NULL;
err_class_create:

	return err;
}


static void __exit pib_ib_cleanup(void)
{
	int i;

	for (i = pib_num_hca - 1 ; 0 <= i ; i--)
		if (pib_ib_devs[i])
			pib_ib_remove(pib_ib_devs[i]);

	pib_kmem_cache_destroy();

	if (dummy_parent_device) {
		device_unregister(dummy_parent_device);
		dummy_parent_device = NULL;
	}

	if (dummy_parent_class) {
		class_destroy(dummy_parent_class);
		dummy_parent_class = NULL;
	}
}


module_init(pib_ib_init);
module_exit(pib_ib_cleanup);
