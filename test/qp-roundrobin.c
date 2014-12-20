/*
 * Check whether a sequnece of QP number is monotonic increasing or not.
 *
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <infiniband/verbs.h>


enum {
	SERVICE_LEVEL = 0
};


static struct {
	int phys_port_cnt;
	struct {
		struct ibv_pd *pd;
	} ibv_port_data[2];
} ibv_device_data[4];


static void do_device(struct ibv_device *ib_dev, int dev_id);
static void do_port(struct ibv_context *context, int dev_id, uint8_t port_num, int max_wqe);

int main(int argc, char** argv)
{
	struct ibv_device **dev_list, **dev_it;

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		fprintf(stderr, "Failed to get IB devices list");
		return 1;
	}

	int dev_id = 0;
	for (dev_it = dev_list ; *dev_it ; dev_it++) {
		do_device(*dev_it, dev_id++);
	}

	ibv_free_device_list(dev_list);
    
	return 0;
}


static void do_device(struct ibv_device *ib_dev, int dev_id)
{
	struct ibv_context *context;

	context = ibv_open_device(ib_dev);
	if (!context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		return;
	}
    
	struct ibv_device_attr device_attr;
	if (ibv_query_device(context, &device_attr)) {
		return;
	}

	ibv_device_data[dev_id].phys_port_cnt = device_attr.phys_port_cnt;

	uint8_t port_num;
	for (port_num = 1 ; port_num < device_attr.phys_port_cnt + 1 ; port_num++) {
		printf("%s %d\n", ibv_get_device_name(ib_dev), port_num);
		do_port(context, dev_id, port_num, device_attr.max_qp_wr);
	}

	if (ibv_close_device(context)) {
		fprintf(stderr, "Couldn't release context\n");
		return;
	}
}


static void do_port(struct ibv_context *context, int dev_id, uint8_t port_num, int max_wqe)
{
	struct ibv_pd  *pd;
	pd = ibv_alloc_pd(context);
	assert(pd);

	struct ibv_cq *cq1, *cq2;
	cq1 = ibv_create_cq(context, max_wqe + 100, NULL, NULL, 0);
	assert(cq1);

	cq2 = ibv_create_cq(context, max_wqe + 100, NULL, NULL, 0);
	assert(cq2);

	ibv_device_data[dev_id].ibv_port_data[port_num - 1].pd = pd;

	uint64_t counter = 0;
	uint32_t prev_qp_num = 0;

	for (;;) {
		struct ibv_qp *qp;
		struct ibv_qp_init_attr qp_attr = {
			.send_cq = cq1,
			.recv_cq = cq2,
			.cap     = {
				.max_send_wr  = max_wqe,
				.max_recv_wr  = max_wqe,
				.max_send_sge = 1,
				.max_recv_sge = 2,
			},
			.qp_type = IBV_QPT_UD,
		};

		qp = ibv_create_qp(pd, &qp_attr);
		if (qp == NULL) {
			printf("ERROR: ibv_create_qp errno=%d\n", errno);
			printf("counter=%lu\n", counter);
			exit(EXIT_FAILURE);
		}

		if (qp->qp_num <= prev_qp_num) {
			printf("%lu: %06x -> %06x\n",
                               counter, prev_qp_num, qp->qp_num);
		}

                prev_qp_num = qp->qp_num;

		ibv_destroy_qp(qp);

		counter++;
	}
}
