/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <infiniband/verbs.h>

enum {
	MAX_MR = 65536
};

struct ibv_mr *mr_array[MAX_MR];

static void usage(const char *argv0)
{
	printf("Usage: [-d <dev>] [-i <port>] [# of MRs]\n");
	printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
	printf("  -s, --size=<size>      allocating size of memory region (default 4096)\n");
}


int main(int argc, char *argv[])
{
	int num_mr = 16;
	size_t size = 4096;
	struct ibv_device *ib_dev;
	char                *ib_devname = NULL;
	int                  ib_port = 1;

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",  .has_arg = 1, .val = 'i' },
			{ .name = "size",     .has_arg = 1, .val = 's' },
			{ 0 }
		};

		c = getopt_long(argc, argv, "d:i:s:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {

		case 'd':
			ib_devname = strdupa(optarg);
			break;

		case 'i':
			ib_port = strtol(optarg, NULL, 10);
			if (ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 's':
			size = strtol(optarg, NULL, 10);
			break;

		default:
			usage(argv[0]);
			return 1;
		}
	}

        if (optind < argc) {
            num_mr = strtol(argv[optind], NULL, 10);
            assert((0 <= num_mr) && (num_mr <= MAX_MR)); 
        }

	struct ibv_device **dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		fprintf(stderr, "Failed to get IB devices list: errnor=%d\n", errno);
		return 1;
	}

	if (!ib_devname) {
		ib_dev = *dev_list;
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			return 1;
		}
	} else {
		int i;
		for (i = 0; dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
				break;
		ib_dev = dev_list[i];
		if (!ib_dev) {
			fprintf(stderr, "IB device %s not found\n", ib_devname);
			return 1;
		}
	}

	struct ibv_context *context = ibv_open_device(ib_dev);
	if (!context) {
		fprintf(stderr, "Couldn't get context for %s: errno=%d\n",
			ibv_get_device_name(ib_dev), errno);
		return 1;
	}

	struct ibv_pd *pd = ibv_alloc_pd(context);
	if (!pd) {
		fprintf(stderr, "Couldn't allocate protection domain: errno=%d\n",
			errno);
		return 1;
	}

	int i;
	for (i = 0 ; i < num_mr ; i++) {
		char *buffer = malloc(size);

		mr_array[i] = ibv_reg_mr(pd, buffer, size, IBV_ACCESS_LOCAL_WRITE);
		if (!mr_array[i]) {
			fprintf(stderr, "Couldn't register memory region: errno=%d\n",
				errno);
			return 1;
		}
		printf("[%2d] %08x %08x\n", i, mr_array[i]->lkey, mr_array[i]->rkey);
	}

	for (i = num_mr - 1 ; i >= 0 ; i--)
		ibv_dereg_mr(mr_array[i]);

	if (ibv_dealloc_pd(pd)) {
		fprintf(stderr, "Couldn't deallocate PD\n");
		return 1;
	}

	if (ibv_close_device(context)) {
		fprintf(stderr, "Couldn't release context\n");
		return 1;
	}

	ibv_free_device_list(dev_list);

	return 0;
}
