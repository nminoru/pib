/*
 * pib.h - General definitions for pib
 *
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#ifndef PIB_H
#define PIB_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/semaphore.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_mad.h> /* for ib_mad_hdr */
#include <rdma/ib_smi.h> /* for ib_smp */


#include "pib_packet.h"


#define PIB_DRIVER_DESCRIPTION	"Pseudo InfiniBand HCA driver"
#define PIB_EASYSW_DESCRIPTION	"Pseudo InfiniBand HCA easy switch"

#define PIB_VERSION_MAJOR	0
#define PIB_VERSION_MINOR	3
#define PIB_VERSION_REVISION	3
#define PIB_DRIVER_VERSION 	"0.3.3"

#define PIB_DRIVER_FW_VERSION \
	(((u64)PIB_VERSION_MAJOR << 32) | ((u64)PIB_VERSION_MINOR << 16) | PIB_VERSION_REVISION)

#define PIB_DRIVER_DEVICE_ID	(1)
#define PIB_DRIVER_REVISION	(1)

/* IB_USER_VERBS_ABI_VERSION */
#define PIB_UVERBS_ABI_VERSION  (6)


#define PIB_NETD_DEFAULT_PORT	(8432)


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
/*
 *  Linux kernels less than 3.13 have the bug that ib_uverbs_post_send() in
 *  uverbs_cmd.c don't set imm_data from ib_uverbs_send_wr to ib_send_wr when 
 *  sending UD messages.
 */
#define PIB_HACK_IMM_DATA_LKEY
#endif

#define PIB_HACK_IPOIB_LEAK_AH

#define PIB_LOCAL_DMA_LKEY		(0)


#define PIB_MAX_HCA			(4)
#define PIB_MAX_PORTS			(32) /* In IBA Spec. Vol.1 17.2.1.3 C17-7.a1, a channel adaptor may support up to 254 ports(1-253).  */
#define PIB_MAX_LID			(0x10000)
#define PIB_MCAST_LID_BASE		(0x0C000)

#define PIB_QP0				(0)
#define PIB_QP1				(1)
#define PIB_MAD_QPS_CORE		(2)
#define PIB_LINK_QP			(3)

#define PIB_MAX_SGE			(32)
#define PIB_MAX_RD_ATOM			(16)

#define PIB_MAX_INLINE			(2048)

#define PIB_QPN_MASK			(0xFFFFFF)
#define PIB_PSN_MASK			(0xFFFFFF)
#define PIB_LOCAL_ACK_TIMEOUT_MASK	(0x1F)
#define PIB_MIN_RNR_NAK_TIMER_MASK	(0x1F)
#define PIB_MAX_MR_PER_PD		(4096)
#define PIB_MR_INDEX_MASK		(PIB_MAX_MR_PER_PD - 1)
#define PIB_PACKET_BUFFER		(8192)
#define PIB_GID_PER_PORT		(16)
#define PIB_MAX_PAYLOAD_LEN	        (0x40000000)

#define PIB_IMM_DATA_LKEY		(0xA0B0C0D0)

#define PIB_SCHED_TIMEOUT		(0x3FFFFFFF) /* 1/4 of max value of unsigned long */

#define PIB_PKEY_PER_BLOCK              (32)
#define PIB_PKEY_TABLE_LEN              (PIB_PKEY_PER_BLOCK * 1)

#define PIB_MCAST_QP_ATTACH             (128)
#define PIB_LID_PERMISSIVE		(0xFFFF)

#define PIB_DEVICE_CAP_FLAGS		(IB_DEVICE_CHANGE_PHY_PORT |\
					 IB_DEVICE_SYS_IMAGE_GUID  |\
					 IB_DEVICE_RC_RNR_NAK_GEN)

#define PIB_PORT_CAP_FLAGS		(IB_PORT_TRAP_SUP|IB_PORT_SYS_IMAGE_GUID_SUP|IB_PORT_CM_SUP)

#define PIB_LINK_WIDTH_SUPPORTED	(IB_WIDTH_1X | IB_WIDTH_4X | IB_WIDTH_8X | IB_WIDTH_12X)
#define PIB_LINK_SPEED_SUPPORTED	(7) /* 2.5 or 5.0 or 10.0 Gbps */
	

#define pib_debug(fmt, args...)					\
	do {							\
		if (pib_debug_level > 0)			\
			printk(KERN_DEBUG fmt, ## args);	\
	} while (0)


enum pib_behavior {
	/*
	 *  IBA Spec. Vol.1 10.2.3 C10-10
	 *  The behavior that the UD-QP's PD doesn't match the PD of AH is
	 *  whether an immediate error or a completion error(IBV_WC_LOC_QP_OP_ERR).
	 */
	PIB_BEHAVIOR_AH_PD_VIOLATOIN_COMP_ERR             =  1,

	/*
	 *  IBA Spec. Vol.1 10.7.2.2 C10-87
	 */
	PIB_BEHAVIOR_RDMA_WRITE_WITH_IMM_ALWAYS_ASYNC_ERR =  2,

	/*
	 *  SRQ の登録順と取り出し順をシャッフルする
	 *
	 *  IBA Spec. Vol.1 10.8.3.2 SHARED RECEIVE QUEUE ORDERING RULES
	 */
	PIB_BEHAVIOR_SRQ_SHUFFLE                          =  3,

	/*
	 *  WC_SUCCESS しない場合に無効なパラメータを乱数値で設定する。
	 *  (opcode, byte_len, imm_data, src_qp, wc_flags, pke_index, slid, sl, did_path_bits)
	 */
	PIB_BEHAVIOR_CORRUPT_INVALID_WC_ATTRS             =  4,

	/*
	 *  空いている若い QPN を再利用する。
	 */
	PIB_BEHAVIOR_QPN_REALLOCATION			  =  5,

	/*
	 *  If the length of a scatter/gather list is zero in bytes,
	 *  it consider as 2^31 in bytes.
	 */
	PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN     = 16
};


enum pib_manner {
	PIB_MANNER_PSN					= 0,
	PIB_MANNER_LOST_WC_WHEN_QP_RESET		= 1,
};


enum pib_hys_port_state_{
	PIB_PHYS_PORT_SLEEP    = 1,
	PIB_PHYS_PORT_POLLING  = 2,
	PIB_PHYS_PORT_DISABLED = 3,
	PIB_PHYS_PORT_PORT_CONFIGURATION_TRAINNING = 4,
	PIB_PHYS_PORT_LINK_UP  = 5,
	PIB_PHYS_PORT_LINK_ERROR_RECOVERY = 6,
	PIB_PHYS_PORT_PHY_TEST = 7
};


enum pib_port_type {
	PIB_PORT_CA = 1,
	PIB_PORT_SW_EXT,
	PIB_PORT_BASE_SP0,
	PIB_PORT_ENH_SP0
};


enum pib_result_type {
	PIB_RES_SCCUESS,
	PIB_RES_IMMEDIATE_RETURN,
	PIB_RES_WR_FLUSH_ERR
};


enum pib_swqe_list {
	PIB_SWQE_FREE      = -1,
	PIB_SWQE_SUBMITTED =  1,
	PIB_SWQE_SENDING,
	PIB_SWQE_WAITING
};


/*
 *  この並びは優先度順
 */
enum pib_thread_flag {
	PIB_THREAD_STOP,
	PIB_THREAD_WQ_SCHEDULE,
	PIB_THREAD_READY_TO_RECV,
	PIB_THREAD_QP_SCHEDULE
};


enum pib_mr_direction {
	PIB_MR_COPY_FROM,
	PIB_MR_COPY_TO,
	PIB_MR_CAS,
	PIB_MR_FETCHADD,
	PIB_MR_CHECK
};


enum pib_obj {
	PIB_MAX_CONTEXT	         =   0x10000,
	PIB_MAX_PD	         =   0x10000,
	PIB_MAX_SRQ	         =   0x10000,
	PIB_MAX_CQ	         =   0x10000,
	PIB_MAX_MR	         =   0x10000,
	PIB_MAX_AH	         = 0x1000000,
	PIB_MAX_QP	         = 0x1000000,

	PIB_BITMAP_CONTEXT_START = 0,
	PIB_BITMAP_PD_START      = PIB_MAX_CONTEXT,
	PIB_BITMAP_SRQ_START     = PIB_BITMAP_PD_START  + PIB_MAX_PD,
	PIB_BITMAP_CQ_START      = PIB_BITMAP_SRQ_START + PIB_MAX_SRQ,
	PIB_BITMAP_MR_START      = PIB_BITMAP_CQ_START  + PIB_MAX_CQ,
	PIB_BITMAP_AH_START      = PIB_BITMAP_MR_START  + PIB_MAX_MR,
	PIB_BITMAP_QP_START      = PIB_BITMAP_AH_START  + PIB_MAX_AH,

	PIB_MAX_OBJS		 = PIB_MAX_CONTEXT + PIB_MAX_PD + PIB_MAX_SRQ + PIB_MAX_CQ + PIB_MAX_MR + PIB_MAX_AH + PIB_MAX_QP,
};


enum pib_state {
	PIB_STATE_OK		= 0,
	PIB_STATE_ERR
};


enum pib_debugfs_type {
	PIB_DEBUGFS_UCONTEXT	= 0,
	PIB_DEBUGFS_PD,
	PIB_DEBUGFS_MR,
	PIB_DEBUGFS_SRQ,
	PIB_DEBUGFS_AH,
	PIB_DEBUGFS_CQ,
	PIB_DEBUGFS_QP,
	PIB_DEBUGFS_LAST
};


enum pib_link_cmd {
	PIB_LINK_CMD_CONNECT	= 1,
	PIB_LINK_CMD_CONNECT_ACK,
	PIB_LINK_CMD_DISCONNECT,
	PIB_LINK_CMD_DISCONNECT_ACK,
	PIB_LINK_SHUTDOWN,
};


struct pib_work_struct {
	bool			on_timer;
	void		       *data;
	struct pib_dev	       *dev;	
	struct list_head	entry;
	void		      (*func)(struct pib_work_struct *);
	struct timer_list	timer;
};


#define PIB_INIT_WORK(_work, _dev, _data, _func)			\
	do {								\
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->data = (_data);				\
		(_work)->dev  = (_dev);					\
		(_work)->func = (_func);				\
		init_timer(&(_work)->timer);				\
	} while (0)


struct pib_mcast_link {
	u16			lid;
	u32			qp_num;
	struct list_head        qp_list;
	struct list_head        lid_list;
};


struct pib_port_perf {
	u8			OpCode; /* all 0xFF */
	u16			tag;
	u16			counter_select[16];
	u64			counter[16];

	u64			symbol_error_counter;
	u64			link_error_recovery_counter;
	u64			link_downed_counter;
	u64			rcv_errors;
	u64			rcv_remphys_errors;
	u64			rcv_switch_relay_errors;
	u64			xmit_discards;
	u64			xmit_constraint_errors;
	u64			rcv_constraint_errors;
	u64			local_link_integrity_errors;
	u64			excessive_buffer_overrun_errors;
	u64			vl15_dropped;
	u64			xmit_data;
	u64			rcv_data;
	u64			xmit_packets;
	u64			rcv_packets;

	u64			xmit_wait;
	
	u64			unicast_xmit_packets;
	u64			unicast_rcv_packets;
	u64			multicast_xmit_packets;
	u64			multicast_rcv_packets;
};


struct pib_port {
	u8                      port_num;
	struct ib_port_attr     ib_port_attr;

	bool			is_connected;

	u8			mkey;
	u8			mkeyprot;
	u16			mkey_lease_period;
	u8			link_down_default_state;
	u8			link_width_enabled;
	u8			link_speed_enabled;
	u8			master_smsl;
	u8			client_reregister;
	u8			subnet_timeout;
	u8			local_phy_errors;
	u8			overrun_errors;

	struct pib_port_perf	perf;  

	struct socket          *socket;
	struct sockaddr        *sockaddr;
	union ib_gid		gid[PIB_GID_PER_PORT];
	struct pib_qp	       *qp_info[PIB_MAD_QPS_CORE];
	u16			pkey_table[PIB_PKEY_TABLE_LEN];

	struct {
		enum pib_link_cmd	cmd;
		struct pib_work_struct	work;
	} link;

	__be16			to_udp_port;	/* for easy swich only */
						/* 通信相手の UDP ポート番号 */
};


struct pib_node {
	u8                      port_count; /* 指定可能なポート数 */
	u8                      port_start;
	struct pib_port	       *ports;
};


struct pib_debugfs_entry {
	struct pib_dev	       *dev; 
	struct dentry  	       *dentry;
	enum pib_debugfs_type	type;
};


struct pib_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr   ib_dev_attr;

	int                     dev_id;

	spinlock_t		lock;

	unsigned long	       *obj_num_bitmap;

	u32			last_ucontext_num;
	int                     nr_ucontext;
	struct list_head        ucontext_head;

	u32			last_pd_num;
	int                     nr_pd;
	struct list_head        pd_head;

	u32			last_mr_num;
	int			nr_mr;
	struct list_head        mr_head;

	u32			last_srq_num;
	int                     nr_srq;
	struct list_head        srq_head;

	u32			last_ah_num;
	int			nr_ah;
	struct list_head        ah_head;

	u32			last_cq_num;
	int                     nr_cq;
	struct list_head        cq_head;

	u32                     last_qp_num;
	int                     nr_qp; /* execept QP0, QP1 */
	struct list_head        qp_head;
	struct rb_root          qp_table;

	struct {
		spinlock_t	lock;
		unsigned long   wakeup_time; /* in jiffies */
		unsigned long   master_tid;
		struct rb_root  rb_root;
	} qp_sched;

	struct {
		spinlock_t	lock;
		struct list_head	head;
		struct list_head	timer_head;
	} wq_sched;

#ifdef PIB_HACK_IMM_DATA_LKEY
	u32                     imm_data_lkey;
#endif

	struct {
		struct task_struct     *task;
		struct completion       completion;
		struct timer_list	timer;  /* Local ACK Tmeout & RNR NAK Timer for RC */

		unsigned long	flags;

		void	       *send_buffer; /* buffer for sendmsg */
		void	       *recv_buffer; /* buffer for recvmsg */
		int		recv_size;

		u8		port_num;
		u16		slid;
		u16		dlid;
		u32		src_qp_num;
		u32		trace_id;
		int		ready_to_send;
	} thread;

	struct list_head       *mcast_table;
	struct pib_port	       *ports;

	struct {
		struct dentry  *dir;

		struct pib_debugfs_entry entries[PIB_DEBUGFS_LAST];

		struct dentry  *inject_err;
		struct pib_work_struct	inject_err_work;
		enum ib_event_type	inject_err_type;
		u32			inject_err_oid;

		struct dentry  *trace;
		void	       *trace_data;
		atomic_t	trace_index;
		spinlock_t	trace_lock; /* for time record */	
		unsigned long   last_record_time;
		int		last_record_time_index;
	} debugfs;
};


struct pib_port_bits {
	u16			pm_blocks[16]; /* portmask blocks */
};


struct pib_easy_sw {
	struct task_struct     *task;
	spinlock_t		lock;
	struct completion       completion;
	unsigned long           flags;
	void                   *buffer; /* buffer for sendmsg/recvmsg */

	struct socket          *socket;
	struct sockaddr        *sockaddr;

	u8                      port_cnt; /* include port 0 */
	struct pib_port	       *ports;

	u16			linear_fdb_top;
	u8			default_port;
	u8			default_mcast_primary_port;
	u8			default_mcast_not_primary_port;
	u8			life_time_value;
	u8			port_state_change;

	u8		       *ucast_fwd_table;
	struct pib_port_bits   *mcast_fwd_table;
};


struct pib_ucontext {
	struct ib_ucontext      ib_ucontext;
	struct list_head        list; /* link to dev->ucontext_head */

	u32			ucontext_num;
	struct timespec		creation_time;
	pid_t			tgid;	
	char			comm[TASK_COMM_LEN];
};


struct pib_pd {
	struct ib_pd            ib_pd;
	struct list_head        list; /* link to dev->pd_head */

	u32			pd_num;
	struct timespec		creation_time;

	spinlock_t		lock;

	int                     nr_mr;
	struct pib_mr	      **mr_table;
};


struct pib_ah {
	struct ib_ah            ib_ah;
	struct ib_ah_attr       ib_ah_attr;
	struct list_head        list; /* link to dev->ah_head */

	u32			ah_num;
	struct timespec		creation_time;
};


struct pib_mr {
	struct ib_mr            ib_mr;
	struct ib_umem         *ib_umem;
	struct list_head        list; /* link to dev->mr_head */

	u32			mr_num;
	struct timespec		creation_time;

	u32                     lkey_prefix;
	u32                     rkey_prefix;
 
	int                     is_dma;
	u64                     start;
	u64                     length;
	u64                     virt_addr;
	int                     access_flags;
};


struct pib_cq {
	struct ib_cq            ib_cq;
	struct list_head        list; /* link to dev->cq_head */

	u32			cq_num;
	struct timespec		creation_time;
	
	spinlock_t		lock;

	enum pib_state		state;
	int			notify_flag;
	int			notified;

	int                     nr_cqe;
	struct list_head        cqe_head;
	struct list_head        free_cqe_head;

	struct pib_work_struct	work; 
};


struct pib_srq {
	struct ib_srq           ib_srq;
	struct ib_srq_attr      ib_srq_attr;
	struct list_head        list; /* link to dev->srq_head */

	u32			srq_num;
	struct timespec		creation_time;

	spinlock_t		lock;

	enum pib_state		state;

	/* list of WRs to be submitted in SRQ. */
	int                     nr_recv_wqe;
	struct list_head        recv_wqe_head;
	struct list_head        free_recv_wqe_head;

	int                     issue_srq_limit; /* set 1 when the async event of SRQ_LIMIT_REACHED is issue */

	struct pib_work_struct	work; 
};


/*
 * To record the result of a previous RMDA READ or Atomic operation.
 */
struct pib_rd_atom_slot {
	u32                     psn;
	u32                     expected_psn;
	int                     OpCode;

	union {
		struct {
			u64     vaddress;
			u32     rkey;
			u32     dmalen;
		} rdma_read;

		struct {
			u64     res;
		} atomic;
	} data;
};


enum pib_ack_type {
	PIB_ACK_NORMAL	= 1,
	PIB_ACK_RMDA_READ,
	PIB_ACK_ATOMIC
};


struct pib_ack {
	struct list_head        list;

	enum pib_ack_type	type;

	u32			psn;
	u32                     expected_psn;

	u32			msn;
	enum pib_syndrome	syndrome;

	union {
		struct {
			u64     vaddress;
			u32     rkey;
			u32     size;
			u32     offset; /* bytes to be transmitted */
		} rdma_read;

		struct {
			u64     res;
		} atomic;
	} data;
};


struct pib_qp {
	struct ib_qp            ib_qp;

	enum ib_qp_type         qp_type;
	enum ib_qp_state        state;
	struct list_head        list; /* link to dev->qp_head */
	struct timespec		creation_time;

	struct pib_cq	       *send_cq;
	struct pib_cq	       *recv_cq;

	struct ib_qp_attr       ib_qp_attr; /* don't use qp_state and cur_qp_state. */ 
	struct ib_qp_init_attr  ib_qp_init_attr;

	struct rb_node          rb_node; /* for dev->qp_table */

	spinlock_t		lock;

	unsigned long           local_ack_timeout; /* in jiffies */

	struct {
		int             on;
		unsigned long   time;
		unsigned long   tid;     /* order by inserting into scheduler */
		struct rb_node  rb_node;
	} sched;

	/* requester side */
	struct {
		u32			psn; /* sq_psn */
		u32			expected_psn;

		/* list of WRs to be new submitted in SQ but not to be processed. */
		int                     nr_submitted_swqe;
		struct list_head        submitted_swqe_head;
		
		/* list of WRs that QP is processing. */
		int                     nr_sending_swqe;
		struct list_head        sending_swqe_head;

		/* list of WRs to be waiting for acknowledge. */
		int                     nr_waiting_swqe;
		struct list_head        waiting_swqe_head;

		int			nr_rd_atomic;

		struct list_head        free_swqe_head;

		void		       *inline_data_buffer;
	} requester;

	/* responder side */
	struct {
		u32			psn; /* rq_psn */
					
		/* list of WRs to be submitted in RQ. */
		int                     nr_recv_wqe;
		struct list_head        recv_wqe_head;

		int			nr_rd_atomic;
		struct list_head        ack_head;

		struct list_head        free_rwqe_head;

		int			last_OpCode;
		u32			offset;

		struct {
			u64		vaddr;
			u32		rkey;
			u32		dmalen;
		} rdma_write;

		int			slot_index;
		struct pib_rd_atom_slot slots[PIB_MAX_RD_ATOM];
	} responder;

	struct list_head	mcast_head;

	int                     push_rcqe;
	int                     issue_comm_est; /* set 1 when the async event of COMM_EST is issue */
	int                     issue_sq_drained;
	int                     issue_last_wqe_reached;
};


struct pib_swqe_processing {
	/* Requester Side */
	enum pib_swqe_list      list_type;
	enum ib_wc_status       status;

	u32                     based_psn;
	u32                     expected_psn;

	u32                     all_packets;
	u32                     ack_packets;
	u32                     sent_packets; /* number of sent packets when SEND or RDMA WRITE */
                                              /* number of received packets when RDMA READ */
	u32                     first_sent_packets;

	unsigned long           schedule_time;
	unsigned long           local_ack_time;

	int                     retry_cnt;
	int                     rnr_retry; 

	/* Responder Side */
};


struct pib_send_wqe {
	u64			wr_id;
	enum ib_wr_opcode	opcode;
	u32			trace_id; /* for execution trace */

	int			send_flags;

	int			num_sge;
	u32                     total_length;
	struct ib_sge           sge_array[PIB_MAX_SGE];

	struct list_head        list; /* link from QP */

	struct pib_swqe_processing processing;

	__be32		        imm_data;
	void		       *inline_data_buffer;

	union {
		struct {
			u64	remote_addr;
			u32	rkey;
		} rdma;

		struct {
			u64	remote_addr;
			u64	compare_add;
			u64	swap;
			u32	rkey;
		} atomic;

		struct {
			struct ib_ah *ah;
			u32	remote_qpn;
			u32	remote_qkey;
			u16	pkey_index; /* valid for GSI only */
			u8	port_num;   /* valid for DR SMPs on switch only */
		} ud;
	} wr;	
};


struct pib_recv_wqe {
	u64			wr_id;
	int			num_sge;
	u32                     total_length;
	struct ib_sge           sge_array[PIB_MAX_SGE];

	struct list_head        list; /* link from QP or SRQ */
};


struct pib_cqe {
	struct ib_wc            ib_wc;
	struct list_head        list;
};


extern bool pib_multi_host_mode;
extern struct sockaddr *pib_netd_sockaddr;
extern int pib_netd_socklen;
extern int pib_debug_level;
extern u64 pib_hca_guid_base;
extern struct pib_dev *pib_devs[];
extern struct pib_easy_sw pib_easy_sw;
extern struct sockaddr **pib_lid_table;
extern unsigned int pib_num_hca;
extern unsigned int pib_phys_port_cnt;
extern unsigned int pib_behavior;
extern unsigned int pib_manner_warn;
extern unsigned int pib_manner_err;
extern struct kmem_cache *pib_ah_cachep;
extern struct kmem_cache *pib_mr_cachep;
extern struct kmem_cache *pib_qp_cachep;
extern struct kmem_cache *pib_cq_cachep;
extern struct kmem_cache *pib_srq_cachep;
extern struct kmem_cache *pib_send_wqe_cachep;
extern struct kmem_cache *pib_recv_wqe_cachep;
extern struct kmem_cache *pib_ack_cachep;
extern struct kmem_cache *pib_cqe_cachep;
extern struct kmem_cache *pib_mcast_link_cachep;


static inline struct pib_dev *to_pdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct pib_dev, ib_dev);
}

static inline struct pib_ucontext *to_pucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct pib_ucontext, ib_ucontext);
}

static inline struct pib_pd *to_ppd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct pib_pd, ib_pd);
}

static inline struct pib_ah *to_pah(struct ib_ah *ibah)
{
	return container_of(ibah, struct pib_ah, ib_ah);
}

static inline struct pib_mr *to_pmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct pib_mr, ib_mr);
}

static inline struct pib_srq *to_psrq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct pib_srq, ib_srq);
}

static inline struct pib_qp *to_pqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct pib_qp, ib_qp);
}

static inline struct pib_cq *to_pcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct pib_cq, ib_cq);
}

static inline int pib_get_behavior(enum pib_behavior behavior)
{
	return (pib_behavior & (1UL << behavior)) != 0;
}

static inline int pib_warn_manner(enum pib_manner manner)
{
	return (pib_manner_warn & (1UL << manner)) != 0;
}

static inline int pib_error_manner(enum pib_manner manner)
{
	return (pib_manner_err & (1UL << manner)) != 0;
}


/*
 *  in pib_main.c
 */
extern struct ib_ucontext *pib_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata);
extern int pib_dealloc_ucontext(struct ib_ucontext *ibcontext);

extern struct ib_pd * pib_alloc_pd(struct ib_device *ibdev, struct ib_ucontext *ibucontext, struct ib_udata *udata);
extern int pib_dealloc_pd(struct ib_pd *ibpd);
extern u32 pib_alloc_obj_num(struct pib_dev *dev, u32 start, u32 size, u32 *last_num_p);
extern void pib_dealloc_obj_num(struct pib_dev *dev, u32 start, u32 index);
extern void pib_fill_grh(struct pib_dev *dev, u8 port_num, struct ib_grh *dest, const struct ib_global_route *src);


/*
 *  in pib_thread.c
 */
extern void pib_util_reschedule_qp(struct pib_qp *qp);
extern struct pib_qp *pib_util_get_first_scheduling_qp(struct pib_dev *dev);

extern int pib_create_kthread(struct pib_dev *dev);
extern void pib_release_kthread(struct pib_dev *dev);
extern int pib_parse_packet_header(void *buffer, int size, struct pib_packet_lrh **lrh_p, struct ib_grh **grh_p, struct pib_packet_bth **bth_p);
extern void pib_netd_comm_handler(struct pib_work_struct *work);
extern void pib_queue_work(struct pib_dev *dev, struct pib_work_struct *work);
extern void pib_queue_delayed_work(struct pib_dev *dev, struct pib_work_struct *work, unsigned long delay);
extern void pib_cancel_work(struct pib_dev *dev, struct pib_work_struct *work);
extern void pib_stop_delayed_queue(struct pib_dev *dev);

/*
 *  in pib_ah.c
 */
extern struct ib_ah *pib_create_ah(struct ib_pd *pd, struct ib_ah_attr *ah_attr);
extern int pib_query_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr);
extern int pib_modify_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr);
extern int pib_destroy_ah(struct ib_ah *ibah);

/*
 *  in pib_mr.c
 */
extern struct ib_mr *pib_get_dma_mr(struct ib_pd *pd, int access_flags);
extern struct ib_mr *pib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				     u64 virt_addr, int access_flags,
				     struct ib_udata *udata);
extern int pib_dereg_mr(struct ib_mr *mr);
extern struct ib_mr *pib_alloc_fast_reg_mr(struct ib_pd *pd,
					   int max_page_list_len);
extern struct ib_fast_reg_page_list *pib_alloc_fast_reg_page_list(struct ib_device *ibdev,
								  int page_list_len);
extern void pib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list);
enum ib_wc_status pib_util_mr_copy_data(struct pib_pd *pd, struct ib_sge *sge_array, int num_sge, void *buffer, u64 offset, u64 size, int access_flags, enum pib_mr_direction direction);
enum ib_wc_status pib_util_mr_validate_rkey(struct pib_pd *pd, u32 rkey, u64 address, u64 size, int access_flag);
enum ib_wc_status pib_util_mr_copy_data_with_rkey(struct pib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction);
enum ib_wc_status pib_util_mr_atomic(struct pib_pd *pd, u32 rkey, u64 address, u64 swap, u64 compare, u64 *result, enum pib_mr_direction direction);

/*
 *  in pib_cq.c
 */
extern struct ib_cq *pib_create_cq(struct ib_device *ibdev, int entries, int vector,
				   struct ib_ucontext *context,
				   struct ib_udata *udata);
extern int pib_destroy_cq(struct ib_cq *ibcq);
extern int pib_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period);
extern int pib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata);
extern int pib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
extern int pib_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
extern int pib_util_remove_cq(struct pib_cq *cq, struct pib_qp *qp);
extern int pib_util_insert_wc_success(struct pib_cq *cq, const struct ib_wc *wc, int solicited);
extern int pib_util_insert_wc_error(struct pib_cq *cq, struct pib_qp *qp, u64 wr_id, enum ib_wc_status status, enum ib_wc_opcode opcode);
extern void pib_util_insert_async_cq_error(struct pib_dev *dev, struct pib_cq *cq);

/*
 *  in pib_srq.c
 */
extern struct ib_srq *pib_create_srq(struct ib_pd *pd,
				     struct ib_srq_init_attr *init_attr,
				     struct ib_udata *udata);
extern int pib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);
extern int pib_query_srq(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
extern int pib_destroy_srq(struct ib_srq *srq);
extern int pib_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *wr,
				 struct ib_recv_wr **bad_wr);
extern struct pib_recv_wqe *pib_util_get_srq(struct pib_srq *srq);
extern void pib_util_insert_async_srq_error(struct pib_dev *dev, struct pib_srq *srq);

/*
 *  in pib_qp.c
 */
extern struct ib_qp *pib_create_qp(struct ib_pd *pd,
				   struct ib_qp_init_attr *init_attr,
				   struct ib_udata *udata);
extern int pib_destroy_qp(struct ib_qp *ibqp);
extern int pib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			 int attr_mask, struct ib_udata *udata);
extern int pib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			struct ib_qp_init_attr *qp_init_attr);
extern int pib_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
			 struct ib_send_wr **bad_wr);
extern int pib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
			 struct ib_recv_wr **bad_wr);
extern void pib_util_free_send_wqe(struct pib_qp *qp, struct pib_send_wqe *send_wqe);
extern void pib_util_free_recv_wqe(struct pib_qp *qp, struct pib_recv_wqe *recv_wqe);
extern struct pib_qp *pib_util_find_qp(struct pib_dev *dev, int qp_num);
extern void pib_util_flush_qp(struct pib_qp *qp, int send_only);
extern void pib_util_insert_async_qp_error(struct pib_qp *qp, enum ib_event_type event);
extern void pib_util_insert_async_qp_event(struct pib_qp *qp, enum ib_event_type event);

/*
 *  in pib_multicast.c
 */
extern int pib_attach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid);
extern int pib_detach_mcast(struct ib_qp *ibqp, union ib_gid *gid, u16 lid);
extern void pib_detach_all_mcast(struct pib_dev *dev, struct pib_qp *qp);

/*
 *  in pib_dma.c 
 */
extern struct ib_dma_mapping_ops pib_dma_mapping_ops;

/*
 *  in pib_ud.c
 */
extern int pib_process_ud_qp_request(struct pib_dev *dev, struct pib_qp *qp, struct pib_send_wqe *send_wqe);
extern void pib_receive_ud_qp_incoming_message(struct pib_dev *dev, u8 port_num, struct pib_qp *qp, struct pib_packet_lrh *lrh, struct ib_grh *grh, struct pib_packet_bth *bth, void *buffer, int size);

/*
 *  in pib_rc.c
 */
extern int pib_process_rc_qp_request(struct pib_dev *dev, struct pib_qp *qp, struct pib_send_wqe *send_wqe);
extern void pib_receive_rc_qp_incoming_message(struct pib_dev *dev, u8 port_num, struct pib_qp *qp, struct pib_packet_lrh *lrh, struct ib_grh *grh, struct pib_packet_bth *bth, void *buffer, int size);
extern int pib_generate_rc_qp_acknowledge(struct pib_dev *dev, struct pib_qp *qp);

/*
 *  in pib_mad.c
 */
extern int pib_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			   struct ib_wc *in_wc, struct ib_grh *in_grh,
			   struct ib_mad *in_mad, struct ib_mad *out_mad);
extern void pib_subn_get_portinfo(struct ib_smp *smp, struct pib_port *port, u8 port_num, enum pib_port_type type);
extern void pib_subn_set_portinfo(struct ib_smp *smp, struct pib_port *port, u8 port_num, enum pib_port_type type);

/*
 *  in pib_perfmgt.c
 */
extern int pib_process_pma_mad(struct pib_node *node, u8 port_num, struct ib_mad *in_mad, struct ib_mad *out_mad);

/*
 *  in pib_easy_sw.c
 */
extern int pib_create_switch(struct pib_easy_sw *sw);
extern void pib_release_switch(struct pib_easy_sw *sw);

/*
 *  in pib_debugfs.c
 */
extern int pib_register_debugfs(void);
extern void pib_unregister_debugfs(void);
extern void pib_inject_err_handler(struct pib_work_struct *work);

/*
 *  in pib_lib.c
 */
extern u32 pib_random(void);
extern const char *pib_get_qp_type(enum ib_qp_type type);
extern const char *pib_get_qp_state(enum ib_qp_state state);
extern const char *pib_get_wc_status(enum ib_wc_status status);
extern const char *pib_get_async_event(enum ib_event_type type);
extern const char *pib_get_uverbs_cmd(int uverbs_cmd);
extern const char *pib_get_trans_op(int op);
extern const char *pib_get_service_type(int op);
extern u32 pib_get_maxium_packet_length(enum ib_mtu mtu);
extern bool pib_is_recv_ok(enum ib_qp_state state);
extern bool pib_is_wr_opcode_rd_atomic(enum ib_wr_opcode opcode);
extern bool pib_opcode_is_acknowledge(int OpCode);
extern bool pib_opcode_is_in_order_sequence(int OpCode, int last_OpCode);
enum ib_wc_opcode pib_convert_wr_opcode_to_wc_opcode(enum ib_wr_opcode);
extern u32 pib_get_num_of_packets(struct pib_qp *qp, u32 length);
extern u32 pib_get_rnr_nak_time(int timeout);
extern unsigned long pib_get_local_ack_time(int timeout);
extern u8 pib_get_local_ca_ack_delay(void);
extern bool pib_is_unicast_lid(u16 lid);
extern bool pib_is_permissive_lid(u16 lid);
extern const char *pib_get_mgmt_method(u8 method);
extern const char *pib_get_smp_attr(__be16 attr_id);
extern const char *pib_get_sa_attr(__be16 attr_id);
extern void pib_print_header(const char *direct, void *buffer);
extern void pib_print_mad(const char *direct, const struct ib_mad_hdr *hdr);
extern void pib_print_smp(const char *direct, const struct ib_smp *smp);

#endif /* PIB_H */
