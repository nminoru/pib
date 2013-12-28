/*
 * Copyright (c) 2013 Minoru NAKAMURA <nminoru@nminoru.jp>
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

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_mad.h> /* for ib_mad_hdr */
#include <rdma/ib_smi.h> /* for ib_smp */


#include "pib_packet.h"


#define PIB_VERSION_MAJOR	0
#define PIB_VERSION_MINOR	1
#define PIB_VERSION_REVISION	0
#define PIB_DRIVER_VERSION 	"0.1.0"

#define PIB_DRIVER_DESCRIPTION	"Pseudo InfiniBand HCA driver"
#define PIB_DRIVER_FW_VERSION \
	(((u64)PIB_VERSION_MAJOR << 32) | ((u64)PIB_VERSION_MINOR << 16) | PIB_VERSION_REVISION)

#define PIB_DRIVER_DEVICE_ID	(1)
#define PIB_DRIVER_REVISION	(1)

/* IB_USER_VERBS_ABI_VERSION */
#define PIB_IB_UVERBS_ABI_VERSION  (6)


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
/*
 *  Linux kernels less than 3.13 have the bug that ib_uverbs_post_send() in
 *  uverbs_cmd.c don't set imm_data from ib_uverbs_send_wr to ib_send_wr when 
 *  sending UD messages.
 */
#define PIB_HACK_IMM_DATA_LKEY
#endif


#define PIB_IB_MAX_HCA			(4)
#define PIB_IB_MAX_PORTS		(32) /* In IBA Spec. Vol.1 17.2.1.3 C17-7.a1, a channel adaptor may support up to 254 ports(1-253).  */
#define PIB_IB_MAX_LID			(65536)

#define PIB_IB_QP0			(0)
#define PIB_IB_QP1			(1)
#define PIB_IB_MAD_QPS_CORE		(2)

#define PIB_IB_MAX_SGE			(32)
#define PIB_IB_MAX_RD_ATOM		(16)

#define PIB_IB_QPN_MASK			(0xFFFFFF)
#define PIB_IB_PSN_MASK			(0xFFFFFF)
#define PIB_IB_LID_BASE			(0xC000)
#define PIB_IB_LOCAL_ACK_TIMEOUT_MASK	(0x1F)
#define PIB_IB_MIN_RNR_NAK_TIMER_MASK	(0x1F)
#define PIB_IB_MAX_MR_PER_PD		(4096)
#define PIB_IB_MR_INDEX_MASK		(PIB_IB_MAX_MR_PER_PD - 1)
#define PIB_IB_PACKET_BUFFER		(8192)
#define PIB_IB_GID_PER_PORT		(16)
#define PIB_IB_MAX_PAYLOAD_LEN	        (0x80000000)

#define PIB_IB_IMM_DATA_LKEY		(0xA0B0C0D0)

#define PIB_SCHED_TIMEOUT		(0x3FFFFFFF) /* 1/4 of max value of unsigned long */

#define PIB_PKEY_TABLE_LEN              (32)

#define PIB_DEVICE_CAP_FLAGS		(IB_DEVICE_SYS_IMAGE_GUID|IB_DEVICE_RC_RNR_NAK_GEN)

#define debug_printk(fmt, args...) \
	printk(KERN_ERR fmt, ## args);


enum pib_behavior {
	/*
	 *  IBA Spec. Vol.1 10.2.3 C10-10
	 *  The behavior that the UD-QP's PD doesn't match the PD of AH is
	 *  whether an immediate error or a completion error(IBV_WC_LOC_QP_OP_ERR).
	 */
	PIB_BEHAVIOR_AH_PD_VIOLATOIN_COMP_ERR             = 1,

	/*
	 *  IBA Spec. Vol.1 10.7.2.2 C10-87
	 */
	PIB_BEHAVIOR_RDMA_WRITE_WITH_IMM_ALWAYS_ASYNC_ERR = 2,

	/*
	 *  If the length of a scatter/gather list is zero in bytes,
	 *  it consider as 2^31 in bytes.
	 */
	PIB_BEHAVIOR_ZERO_LEN_SGE_CONSIDER_AS_MAX_LEN     = 3,

	PIB_BEHAVIOR_SRQ_SHUFFLE                          = 4,
};


enum pib_ib_phys_port_state_{
	PIB_IB_PHYS_PORT_SLEEP    = 1,
	PIB_IB_PHYS_PORT_POLLING  = 2,
	PIB_IB_PHYS_PORT_DISABLED = 3,
	PIB_IB_PHYS_PORT_PORT_CONFIGURATION_TRAINNING = 4,
	PIB_IB_PHYS_PORT_LINK_UP  = 5,
	PIB_IB_PHYS_PORT_LINK_ERROR_RECOVERY = 6,
	PIB_IB_PHYS_PORT_PHY_TEST = 7
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


enum pib_thread_flag {
	PIB_THREAD_READY_TO_DATA,
	PIB_THREAD_SCHEDULE,
	PIB_THREAD_NEW_SEND_WR
};


enum pib_mr_direction {
	PIB_MR_COPY_FROM,
	PIB_MR_COPY_TO,
	PIB_MR_CAS,
	PIB_MR_FETCHADD,
	PIB_MR_CHECK
};


struct pib_dev {
	struct device           dev;
};


struct pib_ib_port {
	u8                      port_num;

	struct ib_port_attr     ib_port_attr;

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

	struct sockaddr       **lid_table;
	struct socket          *socket;
	struct sockaddr        *sockaddr;
	union ib_gid		gid[PIB_IB_GID_PER_PORT];
	struct pib_ib_qp       *qp_info[PIB_IB_MAD_QPS_CORE];
	__be16			pkey_table[PIB_PKEY_TABLE_LEN];
};


struct pib_ib_dev {
	struct ib_device	ib_dev;
	struct ib_device_attr   ib_dev_attr;

	int                     ib_dev_id;

	spinlock_t		lock;

	int                     nr_pd;
	int                     nr_srq;

	u32                     last_qp_num;
	int                     nr_qp;
	struct rb_root          qp_table;

	struct {
		spinlock_t	lock;
		unsigned long   wakeup_time; /* in jiffies */
		unsigned long   master_tid;
		struct rb_root  rb_root;
	} schedule;

	int                     nr_ucontext;
	struct list_head        ucontext_head;

	int                     nr_cq;
	struct list_head        cq_head;

	unsigned int            behavior;
#ifdef PIB_HACK_IMM_DATA_LKEY
	u32                     imm_data_lkey;
#endif

	struct {
		struct task_struct     *task;
		struct completion       completion;
		struct timer_list       timer;  /* Local ACK Tmeout & RNR NAK Timer for RC */
		unsigned long           flags;

		void                   *buffer; /* buffer for sendmsg/recvmsg */

		struct list_head        new_send_wr_qp_head;
	} thread;

	struct pib_ib_port     *ports;

	struct rw_semaphore     rwsem;
};


struct pib_ib_easy_sw {
	struct task_struct     *task;
	spinlock_t		lock;
	struct completion       completion;
	unsigned long           flags;
	struct socket          *socket;
	struct sockaddr        *sockaddr;

	u8                      port_cnt; /* include port 0 */
	struct pib_ib_port     *ports;

	u16			linear_fdb_top;
	u8			default_port;
	u8			default_mcast_primary_port;
	u8			default_mcast_not_primary_port;
	u8			life_time_value;
	u8			port_state_change;

	u8		       *forwarding_table;
};


struct pib_ib_ucontext {
	struct ib_ucontext      ib_ucontext;
};


struct pib_ib_pd {
	struct ib_pd            ib_pd;

	spinlock_t		lock;

	int                     nr_mr;
	struct pib_ib_mr      **mr_table;
};


struct pib_ib_ah {
	struct ib_ah            ib_ah;
	struct ib_ah_attr       ib_ah_attr;
};


struct pib_ib_mr {
	struct ib_mr            ib_mr;
	struct ib_umem         *ib_umem;

	u32                     lkey_prefix;
	u32                     rkey_prefix;
 
	int                     is_dma;
	u64                     start;
	u64                     length;
	u64                     virt_addr;
	int                     access_flags;
};


struct pib_ib_cq {
	struct ib_cq            ib_cq;
	
	spinlock_t		lock;

	int                     nr_cqe;
	struct list_head        cqe_head;
	struct list_head        free_cqe_head;
};


struct pib_ib_srq {
	struct ib_srq           ib_srq;
	struct ib_srq_attr      ib_srq_attr;
	
	/* @todo ステータスが必要 IBA Spec. Vol.1 10.2.9.5 */

	spinlock_t		lock;

	/* list of WRs to be submitted in SRQ. */
	int                     nr_recv_wqe;
	struct list_head        recv_wqe_head;
	struct list_head        free_recv_wqe_head;

	int                     issue_srq_limit; /* set 1 when the async event of SRQ_LIMIT_REACHED is issue */
};


/*
 * To record the result of a previous RMDA READ or Atomic operation.
 */
struct pib_ib_rd_atom_slot {
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


enum pib_ib_ack_type {
	PIB_IB_ACK_NORMAL	= 1,
	PIB_IB_ACK_RMDA_READ,
	PIB_IB_ACK_ATOMIC
};


struct pib_ib_ack {
	struct list_head        list;

	enum pib_ib_ack_type	type;

	u32			psn;
	u32                     expected_psn;

	u32			msn;
	enum pib_ib_syndrome	syndrome;

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


struct pib_ib_qp {
	struct ib_qp            ib_qp;

	enum ib_qp_type         qp_type;
	enum ib_qp_state        state;

	struct pib_ib_cq       *send_cq;
	struct pib_ib_cq       *recv_cq;

	struct ib_qp_attr       ib_qp_attr; /* don't use qp_state and cur_qp_state. */ 
	struct ib_qp_init_attr  ib_qp_init_attr;

	struct rb_node          rb_node; /* for dev->qp_table */

	struct semaphore        sem;

	int                     has_new_send_wr;
	struct list_head        new_send_wr_qp_list;

	struct {
		int             on;
		unsigned long   time;
		unsigned long   tid;     /* order by inserting into scheduler */
		struct rb_node  rb_node;
	} schedule;

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
		struct pib_ib_rd_atom_slot slots[PIB_IB_MAX_RD_ATOM];
	} responder;

	int                     push_rcqe;
	int                     issue_comm_est; /* set 1 when the async event of COMM_EST is issue */
	int                     issue_sq_drained;
	int                     issue_last_wqe_reached;
};


struct pib_ib_swqe_processing {
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


struct pib_ib_send_wqe {
	u64			wr_id;
	enum ib_wr_opcode	opcode;
	int			send_flags;

	int			num_sge;
	u32                     total_length;
	struct ib_sge           sge_array[PIB_IB_MAX_SGE];

	struct list_head        list; /* link from QP */
	struct pib_ib_qp       *qp;

	struct pib_ib_swqe_processing processing;

	__be32		        imm_data;
	
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


struct pib_ib_recv_wqe {
	u64			wr_id;
	int			num_sge;
	u32                     total_length;
	struct ib_sge           sge_array[PIB_IB_MAX_SGE];

	struct list_head        list; /* link from QP or SRQ */
};


struct pib_ib_cqe {
	struct ib_wc            ib_wc; /* @todo 内部の qp は余分 */
	struct list_head        list;
};


extern u64 hca_guid_base;
extern struct pib_ib_dev *pib_ib_devs[];
extern struct pib_ib_easy_sw pib_ib_easy_sw;
extern unsigned int pib_num_hca;
extern unsigned int pib_phys_port_cnt;
extern struct kmem_cache *pib_ib_ah_cachep;
extern struct kmem_cache *pib_ib_mr_cachep;
extern struct kmem_cache *pib_ib_qp_cachep;
extern struct kmem_cache *pib_ib_cq_cachep;
extern struct kmem_cache *pib_ib_srq_cachep;
extern struct kmem_cache *pib_ib_send_wqe_cachep;
extern struct kmem_cache *pib_ib_recv_wqe_cachep;
extern struct kmem_cache *pib_ib_ack_cachep;
extern struct kmem_cache *pib_ib_cqe_cachep;



static inline struct pib_ib_dev *to_pdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct pib_ib_dev, ib_dev);
}

static inline struct pib_ib_ucontext *to_pucontext(struct ib_ucontext *ibucontext)
{
	return container_of(ibucontext, struct pib_ib_ucontext, ib_ucontext);
}

static inline struct pib_ib_pd *to_ppd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct pib_ib_pd, ib_pd);
}

static inline struct pib_ib_ah *to_pah(struct ib_ah *ibah)
{
	return container_of(ibah, struct pib_ib_ah, ib_ah);
}

static inline struct pib_ib_mr *to_pmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct pib_ib_mr, ib_mr);
}

static inline struct pib_ib_srq *to_psrq(struct ib_srq *ibsrq)
{
	return container_of(ibsrq, struct pib_ib_srq, ib_srq);
}

static inline struct pib_ib_qp *to_pqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct pib_ib_qp, ib_qp);
}

static inline struct pib_ib_cq *to_pcq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct pib_ib_cq, ib_cq);
}

static inline int pib_ib_get_behavior(const struct pib_ib_dev *dev, enum pib_behavior behavior)
{
	return (dev->behavior & (1UL << behavior)) != 0;
}
 

extern u32 pib_random(void);

extern struct ib_ucontext *pib_ib_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata);
extern int pib_ib_dealloc_ucontext(struct ib_ucontext *ibcontext);

extern struct ib_pd * pib_ib_alloc_pd(struct ib_device *ibdev, struct ib_ucontext *ibucontext, struct ib_udata *udata);
extern int pib_ib_dealloc_pd(struct ib_pd *ibpd);

extern struct ib_ah *pib_ib_create_ah(struct ib_pd *pd, struct ib_ah_attr *ah_attr);
extern int pib_ib_destroy_ah(struct ib_ah *ah);

extern struct ib_mr *pib_ib_get_dma_mr(struct ib_pd *pd, int access_flags);
extern struct ib_mr *pib_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
					u64 virt_addr, int access_flags,
					struct ib_udata *udata);
extern int pib_ib_dereg_mr(struct ib_mr *mr);
extern struct ib_mr *pib_ib_alloc_fast_reg_mr(struct ib_pd *pd,
					       int max_page_list_len);
extern struct ib_fast_reg_page_list *pib_ib_alloc_fast_reg_page_list(struct ib_device *ibdev,
								     int page_list_len);
extern void pib_ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list);

enum ib_wc_status pib_util_mr_copy_data(struct pib_ib_pd *pd, struct ib_sge *sge_array, int num_sge, void *buffer, u64 offset, u64 size, int access_flags, enum pib_mr_direction direction);
enum ib_wc_status pib_util_mr_validate_rkey(struct pib_ib_pd *pd, u32 rkey, u64 address, u64 size, int access_flag);
enum ib_wc_status pib_util_mr_copy_data_with_rkey(struct pib_ib_pd *pd, u32 rkey, void *buffer, u64 address, u64 size, int access_flags, enum pib_mr_direction direction);
enum ib_wc_status pib_util_mr_atomic(struct pib_ib_pd *pd, u32 rkey, u64 address, u64 swap, u64 compare, u64 *result, enum pib_mr_direction direction);

extern struct ib_srq *pib_ib_create_srq(struct ib_pd *pd,
					 struct ib_srq_init_attr *init_attr,
					 struct ib_udata *udata);
extern int pib_ib_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			      enum ib_srq_attr_mask attr_mask, struct ib_udata *udata);
extern int pib_ib_query_srq(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
extern int pib_ib_destroy_srq(struct ib_srq *srq);
extern int pib_ib_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *wr,
				 struct ib_recv_wr **bad_wr);

extern struct pib_ib_recv_wqe *pib_util_get_srq(struct pib_ib_srq *srq);

extern struct ib_qp *pib_ib_create_qp(struct ib_pd *pd,
				       struct ib_qp_init_attr *init_attr,
				       struct ib_udata *udata);
extern int pib_ib_destroy_qp(struct ib_qp *ibqp);
extern int pib_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			     int attr_mask, struct ib_udata *udata);
extern int pib_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
			    struct ib_qp_init_attr *qp_init_attr);
extern int pib_ib_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
			     struct ib_send_wr **bad_wr);
extern int pib_ib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
			     struct ib_recv_wr **bad_wr);
extern void pib_util_free_send_wqe(struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe);
extern void pib_util_free_recv_wqe(struct pib_ib_qp *qp, struct pib_ib_recv_wqe *recv_wqe);
extern struct pib_ib_qp *pib_util_find_qp(struct pib_ib_dev *dev, int qp_num);
extern void pib_util_flush_qp(struct pib_ib_qp *qp, int send_only);
extern void pib_util_insert_async_qp_error(struct pib_ib_qp *qp, enum ib_event_type event);
extern void pib_util_insert_async_qp_event(struct pib_ib_qp *qp, enum ib_event_type event);

extern void pib_util_reschedule_qp(struct pib_ib_qp *qp);
extern struct pib_ib_qp *pib_util_get_first_scheduling_qp(struct pib_ib_dev *dev);


extern struct ib_cq *pib_ib_create_cq(struct ib_device *ibdev, int entries, int vector,
				      struct ib_ucontext *context,
				      struct ib_udata *udata);
extern int pib_ib_destroy_cq(struct ib_cq *ibcq);
extern int pib_ib_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period);
extern int pib_ib_resize_cq(struct ib_cq *ibcq, int entries, struct ib_udata *udata);
extern int pib_ib_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
extern int pib_ib_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
extern void pib_util_remove_cq(struct pib_ib_cq *cq, struct pib_ib_qp *qp);

extern int pib_util_insert_wc_success(struct pib_ib_cq *cq, const struct ib_wc *wc);
extern int pib_util_insert_wc_error(struct pib_ib_cq *cq, struct pib_ib_qp *qp, u64 wr_id, enum ib_wc_status status, enum ib_wc_opcode opcode);

extern int pib_create_kthread(struct pib_ib_dev *dev);
extern void pib_release_kthread(struct pib_ib_dev *dev);

/*
 *  in pib_dma.c 
 */
extern struct ib_dma_mapping_ops pib_dma_mapping_ops;

/*
 *  in pib_ud.c
 */
extern int pib_process_ud_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe);
extern void pib_receive_ud_qp_SEND_request(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth);

/*
 *  in pib_rc.c
 */
extern int pib_process_rc_qp_request(struct pib_ib_dev *dev, struct pib_ib_qp *qp, struct pib_ib_send_wqe *send_wqe);
extern void pib_receive_rc_qp_incoming_message(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, void *buffer, int size, struct pib_packet_lrh *lrh, struct pib_packet_bth *bth);
extern void pib_generate_rc_qp_acknowledge(struct pib_ib_dev *dev, struct pib_ib_qp *qp);

/*
 *  in pib_mad.c
 */
extern int pib_ib_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			       struct ib_wc *in_wc, struct ib_grh *in_grh,
			       struct ib_mad *in_mad, struct ib_mad *out_mad);
extern void pib_subn_get_portinfo(struct ib_smp *smp, struct pib_ib_port *port, u8 port_num, enum pib_port_type type);
extern void pib_subn_set_portinfo(struct ib_smp *smp, struct pib_ib_port *port, u8 port_num, enum pib_port_type type);

/*
 *  in pib_easy_sw.c
 */
extern int pib_create_switch(struct pib_ib_easy_sw *sw);
extern void pib_release_switch(struct pib_ib_easy_sw *sw);

/*
 *  in pib_lib.c
 */
extern const char *pib_get_qp_type(enum ib_qp_type type);
extern const char *pib_get_qp_state(enum ib_qp_state state);
extern const char *pib_get_wc_status(enum ib_wc_status status);
extern u32 pib_get_maxium_packet_length(enum ib_mtu mtu);
extern int pib_is_recv_ok(enum ib_qp_state state);
extern int pib_opcode_is_acknowledge(int OpCode);
extern int pib_opcode_is_in_order_sequence(int OpCode, int last_OpCode);
enum ib_wc_opcode pib_convert_wr_opcode_to_wc_opcode(enum ib_wr_opcode);
extern u32 pib_get_num_of_packets(struct pib_ib_qp *qp, u32 length);
extern u32 pib_get_rnr_nak_time(int timeout);
extern u32 pib_get_local_ack_time(int timeout);
extern u8 pib_get_local_ca_ack_delay(void);
extern struct sockaddr *pib_get_sockaddr_from_lid(struct pib_ib_dev *dev, u8 port_num, struct pib_ib_qp *qp, u16 lid);
extern void pib_print_mad(const char *direct, const struct ib_mad_hdr *hdr);
extern void pib_print_smp(const char *direct, const struct ib_smp *smp);
extern const char *pib_get_mgmt_method(u8 method);
extern const char *pib_get_smp_attr(__be16 attr_id);


#endif /* PIB_H */
