/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <infiniband/verbs.h>

static void usage(const char *argv0)
{
	printf("Usage: [-d <dev>] [-i <port>]\n");
	printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
}

int main(int argc, char *argv[])
{
	struct ibv_device *ib_dev;
	char                *ib_devname = NULL;
	int                  ib_port = 1;

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",  .has_arg = 1, .val = 'i' },
			{ 0 }
		};

		c = getopt_long(argc, argv, "d:i:", long_options, NULL);
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

		default:
			usage(argv[0]);
			return 1;
		}
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

	size_t size;
	for (size = 1 ; size < 256 * 1024 * 1024 ; size *= 2) {
		char *buffer = malloc(size);
		struct ibv_mr *mr;

		mr = ibv_reg_mr(pd, buffer, size, IBV_ACCESS_LOCAL_WRITE);
		if (mr) {
			printf("ibv_reg_mr: size = %zu OK\n", size);
                } else {
			printf("ibv_reg_mr: size = %zu NG\n", size);
			fprintf(stderr, "Couldn't register memory region: errno=%d\n",
				errno);
			return 1;
		}
		ibv_dereg_mr(mr);
	}

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
