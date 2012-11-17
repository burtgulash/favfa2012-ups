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
static int hangup = 0;
static command_t cmd_set = NIL;

void strip_nls(char *s)
{
	int i = strlen(s);

	while (i > 0) {
		s[--i] = '\0';
	}
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


char *recv_cmd(int s, void *buf, size_t len)
{
	int bs;

	hangup = 0;
	if ((bs = recv(s, buf, len, 0)) <= 0) {
		if (bs == 0)
			hangup = 1;
		return NULL;
	}
	((char *)buf)[bs] = '\0';
	
	if (strncmp(buf, "LOGIN", 5) == 0) {
		cmd_set = LOGIN;
		return buf + 6;
	} if (strncmp(buf, "LOGOUT", 6) == 0) {
		cmd_set = LOGOUT;
		return buf + 7;
	} if (strncmp(buf, "ALL_MSG", 7) == 0) {
		cmd_set = ALL_MSG;
		return buf + 8;
	} if (strncmp(buf, "PRIV_MSG", 8) == 0) {
		cmd_set = PRIV_MSG;
		return buf + 9;
	} if (strncmp(buf, "USERS", 5) == 0) {
		cmd_set = USERS;
		return buf + 6;
	} if (strncmp(buf, "PING", 4) == 0) {
		cmd_set = PING;
		return buf + 5;
	}
// TODO OK
// TODO ERR

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

	user *users = NULL;
	user *ui, *u;

	char *port = DEFAULT_PORT;
	char buf[MAX_DATA_SIZE];
	char *tmp, *cmd;
	int listener_fd, newfd;
	int status;
	int yes = 1;
	int s;
	int bs;
	socklen_t addrlen;
	struct addrinfo hints, *servinfo, *i;
	struct sockaddr_storage their_addr;

	fd_set master_fds, tmp_fds;
	int maxfd;


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
					cmd = recv_cmd(s, buf, sizeof buf - 1);
					if (cmd_set == LOGIN && cmd != NULL) {
						// TODO send OK on successful LOGIN
						tmp = (char *) malloc(sizeof(char) * (strlen(cmd) + 1));
						// FIXME necessary for custom client? 
						// strip_nls(cmd);
						strcpy(tmp, cmd);
						// FIXME remove newline character?
						// tmp[strlen(cmd)] = '\0';
						user_add(&users, tmp, s);
						fprintf(log, "%d User added: \"%s\"\n", s, tmp);
					} else {
						// TODO failed login, send ERR, 
						FD_CLR(s, &master_fds);
						fprintf(log, "%d Failed login\n", s);
					}
				} else {
					cmd = recv_cmd(s, buf, sizeof buf - 1);
					if (cmd != NULL) {
						u = get_user_by_socket(&users, s);
						tmp = cat_name_msg(u->name, cmd);

						switch(cmd_set) {
						case ALL_MSG:
							for (ui = users; ui != NULL; ui = ui->next) {

								// FIXME +1 should be there?
								if (send(ui->socket, tmp, 
										strlen(tmp) + 1, 0) == -1) {
									perror("message send");
									// TODO send ERR
								} else {
									fprintf(log, 
										"%d message from %s to %s: %s\n", 
										u->socket, u->name, ui->name, tmp);
									// all good, message successfully sent
									// TODO send OK
									break;
								}
							}
							// TODO send ERR, already broke if successful
							break;

						// TODO bugged as shit
						case PRIV_MSG:
							tmp = strtok(cmd, " ");						
							if (tmp != NULL) {
								u = get_user_by_socket(&users, s);
								ui = get_user_by_name(&users, tmp);

								tmp = strtok(NULL, " ");
								if (ui != NULL) {
									// FIXME +1 should be there?
									if (send(ui->socket, tmp, 
											strlen(tmp) + 1, 0) == -1) {
										perror("message send");
									} else {
										// all good, message successfully sent
										// TODO send OK
										fprintf(log, 
											"%d message from %s to %s: %s\n", 
											u->socket, u->name, ui->name, tmp);
										break;
									}
								}
							}
							// TODO send ERR, already broke if successful
							break;
						}

						free(tmp);
					} else if (hangup) {
						// TODO disconnect user, remove from master_fds
						close(s);
						FD_CLR(s, &master_fds);
						user_rm(&users, NULL, s);
						fprintf(log, "%d hung up\n", s);
					}
				}
			}
		}
	}
	
	return EXIT_SUCCESS;
}
