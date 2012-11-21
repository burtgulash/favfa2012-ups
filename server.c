#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "user.h"

#define DEFAULT_PORT "1234"
#define BACKLOG 10
#define MAX_DATA_SIZE 1024

typedef enum {NIL, LOGIN, LOGOUT, ALL_MSG, PRIV_MSG, USERS, PING} command_t;

static FILE *log;



static void send_ok(int s)
{
	if (send(s, "OK", 2, 0) == -1)
		perror("OK not sent");
}

static void send_err(int s)
{
	if (send(s, "ERR", 3, 0) == -1)
		perror("ERR not sent");
}

static void send_to_user(user *from, user *to, const void *buf, size_t len)
{
	if (send(to->socket, buf, len, 0) == -1) {
		perror("message send");
		send_err(from->socket);
	} else 
		send_ok(from->socket);
}

static void send_to_all(user **users, user *from, const void *buf, size_t len) 
{
	user *i;

	for (i = *users; i != NULL; i = i->next)
		send_to_user(from, i, buf, len);
}


/*
 * Concatenates name and message together. Result must be freed after using.
 */
static char *cat_name_msg(const char *name, const char *msg)
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


static char *recv_cmd(int s, void *buf, size_t len, command_t *cmd_set, int *hangup)
{
	int bs;

	*hangup = 0;
	if ((bs = recv(s, buf, len, 0)) <= 0) {
		if (bs == 0)
			*hangup = 1;
		return NULL;
	}
	((char *)buf)[bs] = '\0';
	
	if (strncmp(buf, "LOGIN", 5) == 0) {
		*cmd_set = LOGIN;
		return buf + 6;
	} if (strncmp(buf, "LOGOUT", 6) == 0) {
		*cmd_set = LOGOUT;
		return buf + 7;
	} if (strncmp(buf, "ALL_MSG", 7) == 0) {
		*cmd_set = ALL_MSG;
		return buf + 8;
	} if (strncmp(buf, "PRIV_MSG", 8) == 0) {
		*cmd_set = PRIV_MSG;
		return buf + 9;
	} if (strncmp(buf, "USERS", 5) == 0) {
		*cmd_set = USERS;
		return buf + 6;
	} if (strncmp(buf, "PING", 4) == 0) {
		*cmd_set = PING;
		return buf + 5;
	}

	*cmd_set = NIL;
	return NULL;
}

static int sendall(int s, const void *buf, size_t len, int flags) 
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
	char *port = DEFAULT_PORT;

	user *users = NULL;
	char buf[MAX_DATA_SIZE];

	socklen_t addrlen;
	struct addrinfo hints, *servinfo, *i;
	struct sockaddr_storage their_addr;

	fd_set master_fds, tmp_fds;
	int maxfd;

	int s;
	int listener_fd, newfd;
	int hangup;
	command_t cmd_set;




	log = fopen("server.log", "a");
	if (log == NULL)
		log = stdout;

	// TODO remove 
	log = stdout;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;


	int status;
	if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(log, "getaddrinfo: %s\n", gai_strerror(status));	
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

		int yes = 1;
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
		fprintf(log, "server: failed to bind\n");
		exit(2);
	}

	if (listen(listener_fd, BACKLOG) == -1) {
		perror("server: listen");
		exit(2);
	}


	FD_ZERO(&master_fds);
	FD_SET(listener_fd, &master_fds);

	while (1) {
		tmp_fds = master_fds;
		if (select(maxfd + 1, &tmp_fds, NULL, NULL, NULL) == -1) {
			perror("server: select");
			exit(3);
		}

		for (s = 0; s <= maxfd; s++) {
			if (FD_ISSET(s, &tmp_fds)) {
				user *from = get_user(&users, NULL, &s);

				if (s == listener_fd) {
					addrlen = sizeof their_addr;
					newfd = accept(listener_fd, 
									(struct sockaddr*) &their_addr, &addrlen);
					
					if (newfd == -1)
						perror("accept");
					else {
						FD_SET(newfd, &master_fds);
						if (newfd > maxfd)
							maxfd = newfd;
					}
				} else if (from == NULL) {
					char *stripped = recv_cmd(s, buf, sizeof buf - 1, &cmd_set, &hangup);

					if (cmd_set == LOGIN && stripped != NULL) {
						char *user_name = (char *) malloc(sizeof(char) * (strlen(stripped) + 1));
						strcpy(user_name, stripped);

						if (user_name && strlen(user_name) > 0) {
							user_add(&users, user_name, s);
							send_ok(s);
						} else 
							send_err(s);
					} else
						send_err(s);
				} else {
					char *stripped = recv_cmd(s, buf, sizeof buf - 1, &cmd_set, &hangup);

					if (stripped == NULL) {
						if (hangup) {
							close(s);
							FD_CLR(s, &master_fds);

							user *broken = user_rm(&users, NULL, &s);
							if (broken) {
								free(broken->name);
								free(broken);
							}
						}
						break;
					} else {
						user *user_to_logout;
						char *name_msg = cat_name_msg(from->name, stripped);
						char *c;

						switch(cmd_set) {
							case LOGIN:
								send_err(from->socket);
								break;


							case LOGOUT:
								user_to_logout = user_rm(&users, from->name, &from->socket);
								if (user_to_logout) {
									free(user_to_logout->name);
									free(user_to_logout);
									send_ok(s);
								} else 
									send_err(s);
								break;


							case PING:
								send_ok(from->socket);
								break;


							case USERS:
								// TODO new buffer, then split to more sends
								sprintf(buf, "%s", get_all_users(&users));
								if (send(s, buf, strlen(buf), 0) == -1)
									perror("message send");
								break;


							case ALL_MSG:
								send_to_all(&users, from, name_msg, strlen(name_msg));
								break;


							case PRIV_MSG:
								c = strtok(stripped, " ");						
								if (c == NULL)
									break;

printf("user: :::%s:::\n", c);
								user *recipient = get_user(&users, c, NULL);
								if (recipient == NULL) {
printf("proc null?\n");
									send_err(from->socket);
									break;
								}
								c = strtok(NULL, " ");

								send_to_user(from, recipient, c, strlen(c));
								break;

							default:
								assert(0);
								// Shouldn't get here
						}

						free(name_msg);
					}
				}
			}
		}
	}
	
	return EXIT_SUCCESS;
}
