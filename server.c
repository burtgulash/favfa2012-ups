#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "user.h"

#define DEFAULT_PORT "1234"
#define BACKLOG 10
#define MAX_DATA_SIZE 1024

/*
 * Concatenates name and message together. Result must be freed after using.
 */
char * cat_name_msg(const char *name, const char *msg)
{
	size_t len_name, len_msg, len_tmp;
	char *tmp;
	
	len_name = strlen(name);
	len_msg = strlen(msg);
	len_tmp = len_name + 2 + len_msg;

	tmp = (char*) malloc(sizeof(char) * (len_tmp + 1));
	strncpy(tmp, name, len_name);
	strncpy(tmp + len_name + 2, msg, len_msg);

	tmp[len_name] = ':';
	tmp[len_name + 1] = ' ';
	tmp[len_tmp] = '\0';

	return tmp;
}

int sendall(int s, const void *buf, size_t len, int flags) 
{
	size_t sent, left, n;
	
	while (sent < len) {
		n = send(s, buf + sent, left, 0);
		if (n == -1)
			break;
		sent += n;
		left -= n;
	}

	return n;
}

int main()
{
	user *users = NULL;
	user *ui;

	char *port = DEFAULT_PORT;
	char msg_buf[MAX_DATA_SIZE];
	char *tmp;
	int listener_fd, new_fd;
	int status;
	int yes = 1;
	int s;
	int n_bytes;
	socklen_t addrlen;
	struct addrinfo hints, *servinfo, *i;
	struct sockaddr_storage their_addr;

	fd_set master_fds, read_fds;
	int maxfd;


	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;


	if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));	
		exit(1);
	}

	for (i = servinfo; i != NULL; i = i->ai_next) {
		if ((listener_fd = socket(i->ai_family, 
							i->ai_socktype, 
							IPPROTO_TCP)) == -1) {
			perror("server: socket");
			continue;
		}

		maxfd = listener_fd;

		if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, 
						&yes, sizeof(int)) == -1) {
			perror("server: setsockopt");
			exit(1);
		}

		if (bind(listener_fd, i->ai_addr, i->ai_addrlen) == -1) {
			close(listener_fd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (i == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		exit(2);
	}

	if (listen(listener_fd, BACKLOG) == -1) {
		perror("server: listen");
		exit(2);
	}


	FD_ZERO(&master_fds);
	FD_SET(listener_fd, &master_fds);

	while (1) {
		read_fds = master_fds;
		if (select(maxfd + 1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("server: select");
			exit(3);
		}

		for (s = 0; s <= maxfd; s++) {
			if (FD_ISSET(s, &read_fds)) {
				if (s == listener_fd) {
					addrlen = sizeof their_addr;
					new_fd = accept(listener_fd, 
									(struct sockaddr*) &their_addr, &addrlen);
					
					if (new_fd == -1)
						perror("server: accept");
					else {
						/* add test user. */
						user_add(&users, "testovaci", new_fd);
			// printf("user %s added.\n", "testovaci");
						/* TODO login. */
						FD_SET(new_fd, &master_fds);
						if (new_fd > maxfd)
							maxfd = new_fd;
					}
			// printf("server: got connection on socket %d\n", new_fd);
				} else {
					if ((n_bytes = 
							recv(s, msg_buf, sizeof msg_buf, 0)) <= 0) {
						if (n_bytes == 0)
							fprintf(stderr, "socket %d hung up\n", s);
						else
							perror("server: recv");

						close(s);
						FD_CLR(s, &master_fds);
					} else
						printf("received:: %d bytes.\n", n_bytes);
						printf("received:: --<%s>--\n", msg_buf);
						/* Send message to all online users. */
						for (ui = users; ui != NULL; ui = ui->next) {
							tmp = cat_name_msg(ui->name, msg_buf);

				
							if (send(ui->socket, tmp, strlen(tmp) + 1, 0) == -1) {
								perror("server: message send");
							} else {
							printf("sent messgage::   %s\n", tmp);
							}

							free(tmp);
						}
				}
			}
		}
	}
	
	return EXIT_SUCCESS;
}
