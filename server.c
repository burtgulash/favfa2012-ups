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

typedef enum {NIL, LOGIN, LOGOUT, ALL_MSG, PRIV_MSG, USERS, PING} command_t;

void send_to_user(user *recipient, const void *buf, size_t len)
{
	if (send(recipient->socket, buf, len, 0) == -1) {
		perror("message send");
		// TODO send ERR
	} else {
		// TODO OK
		// TODO log
	}
}

void send_to_all(user **users, const void *buf, size_t len) 
{
	user *i;

	for (i = *users; i != NULL; i = i->next)
		send_to_user(i, buf, len);
}


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


char *recv_cmd(int s, void *buf, size_t len, command_t *cmd_set, int *hangup)
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
	FILE *log;
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
	int bs;
	int yes = 1;
	command_t cmd_set;


	// TODO decide if append or write
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
				} else if (get_user_by_socket(&users, s) == NULL) {
					char *stripped = recv_cmd(s, buf, sizeof buf - 1, &cmd_set, &hangup);
					if (cmd_set == LOGIN && stripped != NULL) {
						// TODO send OK on successful LOGIN
						char *tmp = (char *) malloc(sizeof(char) * (strlen(stripped) + 1));
						// FIXME necessary for custom client? 
						// strip_nls(stripped);
						strcpy(tmp, stripped);
						// FIXME remove newline character?
						// tmp[strlen(stripped)] = '\0';
						user_add(&users, tmp, s);
						fprintf(log, "%d User added: \"%s\"\n", s, tmp);
					} else {
						// TODO failed login, send ERR, 
						// FD_CLR(s, &master_fds);
						fprintf(log, "%d Failed login\n", s);
					}
				} else {
					char *stripped = recv_cmd(s, buf, sizeof buf - 1, &cmd_set, &hangup);

					if (stripped == NULL) {
						if (hangup) {
							close(s);
							FD_CLR(s, &master_fds);
							user_rm(&users, NULL, s);
							fprintf(log, "%d hung up\n", s);
						}
						break;
					} else {
						user *u = get_user_by_socket(&users, s);
						char *name_msg = cat_name_msg(u->name, stripped);
						char *c;

						switch(cmd_set) {
						case USERS:
							// TODO new buffer, then split to more sends
							sprintf(buf, "%s", get_all_users(&users));
							if (send(s, buf, strlen(buf) + 1, 0) == -1)
								perror("message send");
							break;

						case ALL_MSG:
							send_to_all(&users, name_msg, strlen(name_msg + 1));
							break;

						// TODO bugged as shit
						case PRIV_MSG:
							c = strtok(stripped, " ");						
							if (c == NULL)
								break;
							user *recipient = get_user_by_name(&users, c);
							if (recipient == NULL) {
								// User doesn't exist!
								break;
							}
							c = strtok(NULL, " ");

							send_to_user(recipient, c, strlen(c) + 1);
							break;
						}

						free(name_msg);
					}
				}
			}
		}
	}
	
	return EXIT_SUCCESS;
}
