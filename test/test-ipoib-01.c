/*
 * Copyright (c) 2014 Minoru NAKAMURA <nminoru@nminoru.jp>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>


enum {
	MAX_IPOIB_NETDEV = 8,
	MAX_RETRY_COUNT  = 100 
};


static int num_ipoib_netdev;

static struct {
	int			sockfd;
	struct sockaddr_in	sockaddr;
} ipoib_netdevs[MAX_IPOIB_NETDEV];


static void setup_sockets(void);
static void run_test(void);
static void test_one_iteration(int from, int to);

int main(int argc, char **argv)
{

	printf(
		"Before this program runs, input the following commands\n"
		"\techo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore\n"
		"\techo 2 > /proc/sys/net/ipv4/conf/all/arp_announce\n\n");

	setup_sockets();

	if (num_ipoib_netdev == 0) {
		fprintf(stderr, "Not found any IPoIB netdev.\n");
		exit(EXIT_FAILURE);
	}

	run_test();

	printf("OK\n");

	return 0;
}


static void setup_sockets(void)
{
	struct ifaddrs *ifaddr, *ifa;
	int family;

	if (getifaddrs(&ifaddr) < 0) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		int sockfd;
		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		if (family != AF_INET)
			continue;

		if (strncmp(ifa->ifa_name, "ib", 2) != 0)
			continue;

		sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
		if (sockfd < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}

		struct sockaddr_in sockaddr;

		memcpy(&sockaddr, ifa->ifa_addr, sizeof(struct sockaddr_in));
		sockaddr.sin_port = 0;

		int ret;

		ret = bind(sockfd, (struct sockaddr*)&sockaddr, (socklen_t)sizeof(sockaddr));
		if (ret < 0) {
			perror("bind");
			exit(EXIT_FAILURE);
		}

#if 0
		ret = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifa->ifa_name, strlen(ifa->ifa_name) + 1);
		if (ret < 0) {
			perror("setsockopt(SO_BINDTODEVICE)");
			exit(EXIT_FAILURE);
		}
#endif

		ipoib_netdevs[num_ipoib_netdev].sockfd   = sockfd;

		socklen_t socklen = sizeof(ipoib_netdevs[num_ipoib_netdev].sockaddr);
		ret = getsockname(sockfd, (struct sockaddr*)&ipoib_netdevs[num_ipoib_netdev].sockaddr,
				  &socklen);
		if (ret < 0) {
			perror("getsockname");
			exit(EXIT_FAILURE);
		}

		printf("setup %s %s:%u\n",
		       ifa->ifa_name,
		       inet_ntoa(ipoib_netdevs[num_ipoib_netdev].sockaddr.sin_addr),
		       ntohs(ipoib_netdevs[num_ipoib_netdev].sockaddr.sin_port));

		num_ipoib_netdev++;
	}

	freeifaddrs(ifaddr);
}


static void run_test(void)
{
	int j, k;
	
	for (j = 0 ; j<num_ipoib_netdev ; j++)
		for (k = j ; k<num_ipoib_netdev ; k++)
			test_one_iteration(j, k);
}


static void test_one_iteration(int from, int to)
{
	char send_buf[8192];
	char recv_buf[8192];

	int t;
	int send_size = ((unsigned int)rand() % 8191) + 1;

	for (t = 0 ; t <send_size; t++)
		send_buf[t] = (char)rand();

	//
	// Send test packet
	//

	ssize_t ret;
	struct iovec iovec;
	struct msghdr msghdr;

	memset(&msghdr,   0, sizeof(msghdr));

	iovec.iov_base     = send_buf;
	iovec.iov_len      = send_size;

	msghdr.msg_name    = &ipoib_netdevs[to].sockaddr;
	msghdr.msg_namelen = sizeof(struct sockaddr_in);
	msghdr.msg_iov     = &iovec;
	msghdr.msg_iovlen  = 1;
			
resend:
	ret = sendmsg(ipoib_netdevs[from].sockfd, &msghdr, 0);
	if (ret < 0) {
		int errnosv = errno;
		switch (errnosv) {
		case EINTR:
		case EAGAIN:
			goto resend;
		default:
			perror("sendmsg");
			exit(EXIT_FAILURE);
			break;
		}
	}

	//
	// Receive test packet
	//

	struct sockaddr_in sockaddr;
	iovec.iov_base     = recv_buf;
	iovec.iov_len      = sizeof(recv_buf);

	msghdr.msg_name    = &sockaddr;
	msghdr.msg_namelen = sizeof(sockaddr);
	msghdr.msg_iov     = &iovec;
	msghdr.msg_iovlen  = 1;

	int retry_count = 0;

rerecv:
	if (MAX_RETRY_COUNT <= retry_count++) {
		printf("Exceed retry limit\n");
		exit(EXIT_FAILURE);
	}

	ret = recvmsg(ipoib_netdevs[to].sockfd, &msghdr, 0);
	if (ret < 0) {
		int errnosv = errno;
		switch (errnosv) {
		case EINTR:
		case EAGAIN:
			goto rerecv;
		default:
			perror("sendmsg");
			exit(EXIT_FAILURE);
			break;
		}
	}

	//
	// Check test packet
	//

	assert(ret == send_size);
	assert(sockaddr.sin_port == ipoib_netdevs[from].sockaddr.sin_port);

	if (send_size > 0)
		assert(memcmp(send_buf, recv_buf, send_size) == 0);
}
