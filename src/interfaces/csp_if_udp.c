/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <csp/interfaces/csp_if_udp.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <csp/csp.h>
#include <csp/csp_endian.h>
#include <csp/csp_interface.h>
#include <csp/arch/csp_thread.h>
#include <csp/csp_id.h>

static int csp_if_udp_tx(const csp_route_t * ifroute, csp_packet_t * packet) {

	csp_if_udp_conf_t * ifconf = ifroute->iface->driver_data;

	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		return CSP_ERR_BUSY;
	}

	csp_id_prepend(packet);

	ifconf->peer_addr.sin_family = AF_INET;
	ifconf->peer_addr.sin_port = htons(ifconf->rport);
	sendto(sockfd, packet->frame_begin, packet->frame_length, MSG_CONFIRM, (struct sockaddr *) &ifconf->peer_addr, sizeof(ifconf->peer_addr));
	csp_buffer_free(packet);

	close(sockfd);

	return CSP_ERR_NONE;
}

static bool running;
void csp_if_udp_stop_rx_task(){
  running = false;
}

CSP_DEFINE_TASK(csp_if_udp_rx_task) {

	csp_iface_t * iface = param;
	csp_if_udp_conf_t * ifconf = iface->driver_data;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in server_addr = {0};
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(ifconf->lport);

	fd_set socks;
	FD_ZERO(&socks);
	FD_SET(sockfd, &socks);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));
	struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};

    running = true;
	while(running) {

		if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
			printf("UDP server waiting for port %d\n", ifconf->lport);
			sleep(1);
			continue;
		}

		while(running) {

			csp_packet_t * packet = csp_buffer_get(iface->mtu);
			if (packet == NULL) {
				csp_sleep_ms(10);
				continue;
			}

			/* Setup RX frane to point to ID */
			int header_size = csp_id_setup_rx(packet);

			unsigned int peer_addr_len = sizeof(ifconf->peer_addr);
			int received_len = recvfrom(sockfd, (char *) packet->frame_begin, iface->mtu + header_size, MSG_WAITALL, (struct sockaddr *) &ifconf->peer_addr, &peer_addr_len);
			packet->frame_length = received_len;

			csp_log_info("UDP peer address: %s", inet_ntoa(ifconf->peer_addr.sin_addr));

			/* Parse the frame and strip the ID field */
			if (csp_id_strip(packet) != 0) {
				iface->rx_error++;
				csp_buffer_free(packet);
				continue;
			}

			csp_qfifo_write(packet, iface, NULL);


		}

	}

	csp_thread_exit();

	return CSP_TASK_RETURN;

}

void csp_if_udp_init(csp_iface_t * iface, csp_if_udp_conf_t * ifconf) {

	iface->driver_data = ifconf;

	if (inet_aton(ifconf->host, &ifconf->peer_addr.sin_addr) == 0) {
		printf("Unknown peer address %s\n", ifconf->host);
	}

	printf("UDP peer address: %s:%d (listening on port %d)\n", inet_ntoa(ifconf->peer_addr.sin_addr), ifconf->rport, ifconf->lport);

	/* Start server thread */
	int ret = csp_thread_create(csp_if_udp_rx_task, "UDPS", 10000, iface, 0, &ifconf->server_handle);
	csp_log_info("csp_if_udp_rx_task start %d\r\n", ret);

	/* MTU is datasize */
	iface->mtu = csp_buffer_data_size();

	/* Regsiter interface */
	iface->name = "UDP",
	iface->nexthop = csp_if_udp_tx,
	csp_iflist_add(iface);

}

/* void csp_if_udp_init_w_port(csp_iface_t * iface, char * host, size_t port) { */
/* 	_udp_port = port; */
/* 	csp_if_udp_init(iface, host); */
/* } */
