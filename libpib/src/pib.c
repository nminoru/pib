/*
 * Copyright (c) 2013,2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include <infiniband/driver.h>


struct pib_ibv_device {
	struct ibv_device	base;
	uint32_t		imm_data_lkey;
};


static int pib_query_device(struct ibv_context *context,
			    struct ibv_device_attr *device_attr)
{
	struct ibv_query_device cmd;
	uint64_t raw_fw_ver;
	unsigned major, minor, sub_minor;
	int ret;

	ret = ibv_cmd_query_device(context, device_attr, &raw_fw_ver, &cmd, sizeof cmd);
	if (ret)
		return ret;

	major     = (raw_fw_ver >> 32) & 0xffff;
	minor     = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(device_attr->fw_ver, sizeof device_attr->fw_ver,
		 "%d.%d.%03d", major, minor, sub_minor);

	return 0;
}

static int pib_query_port(struct ibv_context *context, uint8_t port_num,
			  struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(context, port_num, port_attr, &cmd, sizeof cmd);
}

static struct ibv_pd *pib_alloc_pd(struct ibv_context *context)
{
	struct ibv_pd *pd;
	struct ibv_alloc_pd cmd;
	struct ibv_alloc_pd_resp resp;
	int ret;

	pd = calloc(1, sizeof *pd);
	if (!pd)
		return NULL;

	ret = ibv_cmd_alloc_pd(context, pd, 
			       &cmd, sizeof cmd, 
			       &resp, sizeof resp);
	if (ret) {
		free(pd);
		errno = ret;
		return NULL;
	}

	return pd;
}

static int pib_dealloc_pd(struct ibv_pd *pd)
{
	int ret;

	ret = ibv_cmd_dealloc_pd(pd);

	if (pd)
		free(pd);

	return ret;
}

static struct ibv_mr *pib_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
				 int access)
{
	struct ibv_mr *mr;
	struct ibv_reg_mr cmd;
	struct ibv_reg_mr_resp resp;
	int ret;

	mr = calloc(1, sizeof *mr);
	if (!mr)
		return NULL;

	ret = ibv_cmd_reg_mr(pd, addr, length,
			     (uintptr_t)addr, /* hca_va */
			     access, mr, &cmd, sizeof cmd,
			     &resp, sizeof resp);
	if (ret) {
		free(mr);
		errno = ret;
		return NULL;
	}

	return mr;
}

struct ibv_mr *pib_rereg_mr(struct ibv_mr *mr,
			    int flags,
			    struct ibv_pd *pd, void *addr,
			    size_t length,
			    int access)
{
	errno = ENOSYS;

	return NULL;
}

static int pib_dereg_mr(struct ibv_mr *mr)
{
	int ret;

	ret = ibv_cmd_dereg_mr(mr);

	if (mr)
		free(mr);

	return ret;
}

static struct ibv_mw *pib_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type)
{
	errno = ENOSYS;

	return NULL;
}

static int pib_bind_mw(struct ibv_qp *qp, struct ibv_mw *mw,
		       struct ibv_mw_bind *mw_bind)
{
	errno = ENOSYS;

	return -1;
}

static int pib_dealloc_mw(struct ibv_mw *mw)
{
	errno = ENOSYS;

	return -1;
}

static struct ibv_cq *pib_create_cq(struct ibv_context *context, int cqe,
				    struct ibv_comp_channel *channel,
				    int comp_vector)
{
	struct ibv_cq *cq;
	struct ibv_create_cq cmd;
	struct ibv_create_cq_resp resp;
	int ret;

	cq = calloc(1, sizeof *cq);
	if (!cq)
		return NULL;

	ret = ibv_cmd_create_cq(context, cqe, channel, comp_vector,
				cq,
				&cmd, sizeof cmd,
				&resp, sizeof resp);
	if (ret) { 
		free(cq);
		errno = ret;
		return NULL;
	}

	return cq;
}

static int pib_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{
	return ibv_cmd_poll_cq(cq, num_entries, wc);
}

static int pib_req_notify_cq(struct ibv_cq *cq, int solicited_only)
{
	return ibv_cmd_req_notify_cq(cq, solicited_only);
}

static int pib_resize_cq(struct ibv_cq *cq, int cqe)
{
	struct ibv_resize_cq cmd;
	struct ibv_resize_cq_resp resp;

	return ibv_cmd_resize_cq(cq, cqe,
				 &cmd, sizeof cmd,
				 &resp, sizeof resp);
}

static int pib_destroy_cq(struct ibv_cq *cq)
{
	int ret;

	ret = ibv_cmd_destroy_cq(cq);

	if (cq)
		free(cq);

	return ret;
}

static struct ibv_srq *pib_create_srq(struct ibv_pd *pd,
				      struct ibv_srq_init_attr *srq_init_attr)
{
	struct ibv_srq *srq;
	struct ibv_create_srq cmd;
	struct ibv_create_srq_resp resp;
	int ret;

	srq = calloc(1, sizeof *srq);
	if (!srq)
		return NULL;

	ret = ibv_cmd_create_srq(pd, srq, srq_init_attr,
				 &cmd, sizeof cmd,
				 &resp, sizeof resp);
	if (ret) { 
		free(srq);
		errno = ret;
		return NULL;
	}

	return srq;
}

static int pib_modify_srq(struct ibv_srq *srq,
			  struct ibv_srq_attr *srq_attr,
			  int srq_attr_mask)
{
	struct ibv_modify_srq cmd;

	return ibv_cmd_modify_srq(srq, srq_attr, srq_attr_mask,
				  &cmd, sizeof cmd);
}

static int pib_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(srq, srq_attr,
				 &cmd, sizeof cmd);
}

static int pib_destroy_srq(struct ibv_srq *srq)
{
	int ret;

	ret = ibv_cmd_destroy_srq(srq);

	if (srq)
		free(srq);

	return ret;
}

static int pib_post_srq_recv(struct ibv_srq *srq,
			     struct ibv_recv_wr *recv_wr,
			     struct ibv_recv_wr **bad_recv_wr)
{
	return ibv_cmd_post_srq_recv(srq, recv_wr, bad_recv_wr);
}

static struct ibv_qp *pib_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct ibv_qp *qp;
	struct ibv_create_qp cmd;
	struct ibv_create_qp_resp resp;
	int ret;

	qp = calloc(1, sizeof *qp);
	if (!qp)
		return NULL;

	ret = ibv_cmd_create_qp(pd, qp, attr,
				&cmd, sizeof cmd,
				&resp, sizeof resp);
	if (ret) {
		free(qp);
		errno = ret;
		return NULL;
	}

	return qp;
}

static int pib_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			int attr_mask,
			struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	
	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr,
				&cmd, sizeof cmd);
}

static int pib_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			 int attr_mask)
{
	struct ibv_modify_qp cmd;

	return ibv_cmd_modify_qp(qp, attr, attr_mask,
				 &cmd, sizeof cmd);
}

static int pib_destroy_qp(struct ibv_qp *qp)
{
	int ret;

	ret = ibv_cmd_destroy_qp(qp);

	if (qp)
		free(qp);

	return ret;
}

static int ud_qp_post_send_with_imm(struct ibv_qp *qp, struct ibv_send_wr *wr,
				    struct ibv_send_wr **bad_wr, uint32_t imm_data_lkey)
{
	int i;
	struct ibv_send_wr wr_temp = *wr;

	wr_temp.next    = NULL;

	if (wr_temp.opcode != IBV_WR_SEND_WITH_IMM)
		goto done;

	/* Add special a s/g entry */

	wr_temp.sg_list = (struct ibv_sge*)alloca(sizeof(struct ibv_sge) * (wr_temp.num_sge + 1));

	for (i=0 ; i<wr_temp.num_sge ; i++)
		wr_temp.sg_list[i] = wr->sg_list[i];

	wr_temp.sg_list[i].addr   = 0; 
	wr_temp.sg_list[i].length = wr->imm_data;
	wr_temp.sg_list[i].lkey   = imm_data_lkey;
		
	wr_temp.num_sge++;

done:
	return ibv_cmd_post_send(qp, &wr_temp, bad_wr);
}

static int pib_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{
	uint32_t imm_data_lkey;
	struct ibv_send_wr *i;

	if (qp->qp_type == IBV_QPT_UD && qp->context->device) {
		imm_data_lkey = ((struct pib_ibv_device*)qp->context->device)->imm_data_lkey;
		if (imm_data_lkey)
			goto hack_imm_data_lkey;
	}

	return ibv_cmd_post_send(qp, wr, bad_wr);

hack_imm_data_lkey:
	for (i = wr; i ; i = i->next) {
		int ret;
		ret = ud_qp_post_send_with_imm(qp, i, bad_wr, imm_data_lkey);
		if (ret) {
			*bad_wr = i;
			return ret;
		}
	}

	return 0;
}

static int pib_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	return ibv_cmd_post_recv(qp, wr, bad_wr);
}

static int pib_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return ibv_cmd_attach_mcast(qp, gid, lid);
}

static int pib_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	return ibv_cmd_detach_mcast(qp, gid, lid);
}

static struct ibv_ah *pib_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	struct ibv_ah *ah;
	int ret;

	ah = calloc(1, sizeof *ah);
	if (!ah)
		return NULL;

	ret = ibv_cmd_create_ah(pd, ah, attr);
	if (ret) {
		free(ah);
		errno = ret;
		return NULL;
	}

	return ah;
}

static int pib_destroy_ah(struct ibv_ah *ah)
{
	int ret;

	ret = ibv_cmd_destroy_ah(ah);

	if (ah)
		free(ah);

	return ret;
}

static void pib_cq_event(struct ibv_cq *cq)
{
	/* ibv_get_cq_event の下請けだが channel->fd が直接返すなら不要 */
}

static void pib_async_event(struct ibv_async_event *event)
{
	/* ibv_get_async_event が context->async_fd を直接返すだけなら不要 */
}

static struct ibv_context_ops pib_ctx_ops = {
	.query_device  = pib_query_device,
	.query_port    = pib_query_port,
	.alloc_pd      = pib_alloc_pd,
	.dealloc_pd    = pib_dealloc_pd,
	.reg_mr	       = pib_reg_mr,
	.dereg_mr      = pib_dereg_mr,
	.alloc_mw      = pib_alloc_mw,
	.bind_mw       = pib_bind_mw,
	.dealloc_mw    = pib_dealloc_mw,
	.create_cq     = pib_create_cq,
	.poll_cq       = pib_poll_cq,
	.req_notify_cq = pib_req_notify_cq,
	.cq_event      = pib_cq_event,
	.resize_cq     = pib_resize_cq,
	.destroy_cq    = pib_destroy_cq,
	.create_srq    = pib_create_srq,
	.modify_srq    = pib_modify_srq,
	.query_srq     = pib_query_srq,
	.destroy_srq   = pib_destroy_srq,
	.post_srq_recv = pib_post_srq_recv,
	.create_qp     = pib_create_qp,
	.query_qp      = pib_query_qp,
	.modify_qp     = pib_modify_qp,
	.destroy_qp    = pib_destroy_qp,
	.post_send     = pib_post_send,
	.post_recv     = pib_post_recv,
	.create_ah     = pib_create_ah,
	.destroy_ah    = pib_destroy_ah,
	.attach_mcast  = pib_attach_mcast,
	.detach_mcast  = pib_detach_mcast,
	.async_event   = pib_async_event,
};

static struct ibv_context *pib_alloc_context(struct ibv_device *ibdev, int cmd_fd)
{
	struct ibv_context *context;
	struct ibv_get_context cmd;
	struct ibv_get_context_resp resp;
	int ret;

	context = calloc(1, sizeof *context);
	if (!context)
		return NULL;

	context->cmd_fd = cmd_fd;
	
	ret = ibv_cmd_get_context(context,
				  &cmd, sizeof cmd,
				  &resp, sizeof resp);
	if (ret) {
		free(context);
		errno = ret;
		return NULL;
	}

	context->ops = pib_ctx_ops;

	return context;
}

static void pib_free_context(struct ibv_context *context)
{
	if (context)
		free(context);
}

static struct ibv_device_ops pib_dev_ops = {
	.alloc_context = pib_alloc_context,
	.free_context  = pib_free_context
};

static struct ibv_device *pib_driver_init(const char *uverbs_sys_path, int abi_version)
{
	char device_name[24];
	struct pib_ibv_device *dev;
	char ibdev_path[IBV_SYSFS_PATH_MAX];
	char attr[41];

	if (ibv_read_sysfs_file(uverbs_sys_path, "ibdev",
				device_name, sizeof device_name) < 0)
		return NULL;

	if (strncmp(device_name, "pib_", 4) != 0)
		return NULL;

	dev = calloc(1, sizeof *dev);
	if (!dev) {
		return NULL;
	}

	dev->base.ops            = pib_dev_ops;
	dev->base.node_type      = IBV_NODE_CA;
	dev->base.transport_type = IBV_TRANSPORT_IB;

	snprintf(ibdev_path, sizeof ibdev_path,
		 "%s/class/infiniband/%s", ibv_get_sysfs_path(),
		 device_name);
	
	if (ibv_read_sysfs_file(ibdev_path, "imm_data_lkey",
				attr, sizeof attr) < 0)
		goto done;

	if (sscanf(attr, "0x%08x", &dev->imm_data_lkey) != 1)
		dev->imm_data_lkey = 0U;

done:
	return &dev->base;
}

static __attribute__((constructor)) void pib_register_driver(void)
{
	ibv_register_driver("pib", pib_driver_init);
}
