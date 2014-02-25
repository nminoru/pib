/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 *
 * This code is licenced under the GPL version 2 or BSD license.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pibnetd.h"

static int verbose;
static uint32_t port_num = PIB_NETD_DEFAULT_PORT;

int main(int argc, char** argv)
{
	struct option longopts[] = {
		{"port",     required_argument, NULL, 'p' },
		{"verbose",  no_argument,       NULL, 'v' },
	};

	int ch, option_index;

	while ((ch = getopt_long(argc, argv, "p:v", longopts, &option_index)) != -1) {
		switch (ch) {

		case 'p':
			port_num = atoi(optarg);
			assert((0 < port_num) && (port_num < 65536));
			break;

		case 'v': // verbose
			verbose = 1;
			break;

		default:
			break;
		}
	}

	int sockfd;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		int eno  = errno;
		fprintf(stderr, "pibping: socket(errno=%d)\n", eno);
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family      = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	sockaddr.sin_port        = 0;

	int ret = bind(sockfd, (struct sockaddr*)&sockaddr, (socklen_t)sizeof(sockaddr));
	if (ret != 0) {
		int eno  = errno;
		fprintf(stderr, "pibping: bind(errno=%d)\n", eno);
		exit(EXIT_FAILURE);
	}

	char buffer[4096];
	struct msghdr msghdr;
	struct iovec iovec;

	sockaddr.sin_port  = htons(port_num);

	iovec.iov_base     = buffer;
	iovec.iov_len      = sizeof(buffer);
	msghdr.msg_name    = &sockaddr;
	msghdr.msg_namelen = sizeof(sockaddr);

	msghdr.msg_iov     = &iovec;
	msghdr.msg_iovlen  = 1;

	ret = sendmsg(sockfd, &msghdr, 0);
	printf("sendmsg: ret=%d\n", ret);

	return 0;
}
