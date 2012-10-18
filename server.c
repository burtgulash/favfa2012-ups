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

#define BACKLOG 10
#define MAX_DATA_SIZE 1024

int main()
{
	user *users = NULL;

	char *port = "1234";
	int sockfd, newfd;
	int status;
	int yes = 1;
	socklen_t sin_size;
	struct addrinfo hints, *servinfo, *i;
	struct sockaddr_storage their_addr;

	fd_set socks;
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
		if ((sockfd = socket(i->ai_family, 
							i->ai_socktype, 
							IPPROTO_TCP)) == -1) {
			perror("server: socket");
			continue;
		}

		maxfd = sockfd;

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 
						&yes, sizeof(int)) == -1) {
			perror("server: setsockopt");
			exit(1);
		}

		if (bind(sockfd, i->ai_addr, i->ai_addrlen) == -1) {
			close(sockfd);
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

	if (listen(sockfd, BACKLOG) == -1) {
		perror("server: listen");
		exit(2);
	}


	FD_ZERO(&socks);
	FD_SET(sockfd, &socks);

	select(maxfd + 1, &socks, NULL, NULL, NULL);

	while (1) {
		if ((newfd = accept(sockfd, 
					(struct sockaddr*) &their_addr, 
					&sin_size)) == -1) {
			perror("server: accept");
			continue;
		}

		if (recv(newfd, buf, MAX_DATA_SIZE, 0) == -1) {
			perror("server: login");
			continue;
		}

		/* TODO Error checking of name, size, etc.. */
		if (strncmp("LOGIN", buf, 5) == 0)
			user_add(&users, buf + 5 + 1, newfd);
	}
	
	return EXIT_SUCCESS;
}
