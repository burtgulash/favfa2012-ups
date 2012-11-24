#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
	if (send(s, "OK\n", 3, 0) == -1)
		perror("OK not sent");
}

static void send_err(int s)
{
	if (send(s, "ERR\n", 4, 0) == -1)
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
	int all_good = 1;

	for (i = *users; i != NULL; i = i->next)
		if (send(i->socket, buf, len, 0) == -1) {
			perror("message send");
			all_good = 0;
		}

	if (all_good)
		send_ok(from->socket);
	else
		send_err(from->socket);
}


/*
 * Concatenates name and message together. Result must be freed after using.
 */
static char *concatenate(int n, ...)
{
	char *res, *p, *arg;
	int i, j;
	size_t len = 0;
	va_list argp;
	
	if (n == 0)
		return NULL;

	va_start(argp, n);
	for (i = 0; i < n; i++)
		len += strlen(va_arg(argp, char *));
	va_end(argp);

	res = p = (char *) malloc(len + 2);

	va_start(argp, n);
	for (i = 0; i < n; i++) {
		arg = va_arg(argp, char *);
		len = strlen(arg);
		strncpy(p, arg, len);
		p += len;
	}
	va_end(argp);

	*p = '\n';
	*(p + 1) = '\0';

	return res;
}

void strip_nls(char *buf)
{
	char *p = buf + strlen(buf) - 1;

	while (p && (*p == '\r' || *p == '\n'))
		*p-- = '\0';
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
	strip_nls(buf);
	
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
					if (stripped == NULL) {
						if (hangup) {
							close(s);
							FD_CLR(s, &master_fds);
						} else
							send_err(s);

						break;
					}

					if (cmd_set == LOGIN) {
						char *user_name = (char *) malloc(sizeof(char) * (strlen(stripped) + 1));
						strcpy(user_name, stripped);

						if (user_name 
							&& strlen(user_name) > 0
							&& get_user(&users, user_name, NULL) == NULL) 
						{
							user_add(&users, user_name, s);
							send_ok(s);
						} else {
							free(user_name);
							send_err(s);
						}
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
						} else
							send_err(from->socket);

						break;
					}

					char *from_msg;

					switch(cmd_set) {
						case LOGIN:
							send_err(from->socket);
							break;


						case LOGOUT:;
							user *user_to_logout = user_rm(&users, from->name, &from->socket);
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


						case USERS:;
							user *i;
							int len, buflen;
							char *tmp_buf, *p;

							len = buflen = 0;

							for (i = users; i != NULL; i = i->next) {
								len ++;
								buflen += strlen(i->name);

								/* Account for a newline between names. */
								if (len > 1)
									buflen ++;
							}

							tmp_buf = p = (char*) malloc(buflen + 1);

							for (i = users; i != NULL; i = i->next) {
								strcpy(p, i->name);
								p += strlen(i->name);
								*p++ = ' ';
							}
							*(p - 1) = '\n';
							*p = '\0';

							// TODO new buffer, then split to more sends
							send_to_user(from, from, tmp_buf, strlen(tmp_buf));

							free(tmp_buf);
							break;


						case ALL_MSG:;
							from_msg = concatenate(4, "ALL_MSG ", from->name, " -> ", stripped);
							send_to_all(&users, from, from_msg, strlen(from_msg));
							free(from_msg);
							break;


						case PRIV_MSG:;
							char *c = strtok(stripped, " ");						
							if (c == NULL)
								break;

							user *recipient = get_user(&users, c, NULL);
							if (recipient == NULL) {
								send_err(from->socket);
								break;
							}
							c = strtok(NULL, " ");

							from_msg = concatenate(4, "PRIV_MSG ", from->name, " -> ", c);
							send_to_user(from, recipient, from_msg, strlen(from_msg));
							free(from_msg);
							break;


						case NIL:
							// shouldn't happen?
							send_err(from->socket);
							break;


						default:
							assert(0);
							// Shouldn't get here
					}
				}
			}
		}
	}
	
	return EXIT_SUCCESS;
}
