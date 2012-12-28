#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "user.h"

#define DEFAULT_PORT "1234"
#define BACKLOG 10
#define MAX_DATA_SIZE 1024
#define ID_SIZE 3

#define LOG_FILE "server.log"


typedef enum {NIL, LOGIN, LOGOUT, ALL_MSG, PRIV_MSG, USERS, PING} command_t;

static int log_exists = 0;
static int terminated = 0;
static pthread_mutex_t terminate_lock;


void *interactive_loop(void *ptr)
{
	char input[50];

	while(1) {
		printf("[t]erm to terminate server.\n");
		printf("[d]ata for info on transferred data.\n");
		printf("\n");

		
		printf(">> ");
		scanf("%s", input);
		if (input && (input[0] == 't' || strcmp(input, "term") == 0)) {
			pthread_mutex_lock(&terminate_lock);
			terminated = 1;
			pthread_mutex_unlock(&terminate_lock);

			break;
		} else if (input && (input[0] == 'd' || strcmp(input, "data") == 0)) {
			printf("transferred.... TODO\n");
		}
	}
}

void server_log(int s, const char *what, ...)
{
	time_t rawtime;
	struct tm *timeinfo;
	char *asc;
	char ip[INET6_ADDRSTRLEN];
	socklen_t len;
	struct sockaddr_storage addr;
	FILE *file;
	va_list args;

	memset(ip, ' ', sizeof ip);
	ip[sizeof ip - 1] = '\0';

	len = sizeof addr;
	if (getpeername(s, (struct sockaddr *) &addr, &len) != -1) {
		if (addr.ss_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *) &addr;
			inet_ntop(AF_INET, &ipv4->sin_addr, ip, sizeof ip);
		} else {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) &addr;
			inet_ntop(AF_INET6, &ipv6->sin6_addr, ip, sizeof ip);
		}
	}

	if (!log_exists) {
		file = fopen(LOG_FILE, "w");
		log_exists = 1;
	} else
		file = fopen(LOG_FILE, "a");

	if (file == NULL) {
		log_exists = 0;
	} else {
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		asc = asctime(timeinfo);
		asc[strlen(asc) - 1] = '\0';

		fprintf(file, "%s -- ", ip);

		fprintf(file, "[%s] ", asc);

		va_start(args, what);
		vfprintf(file, what, args);
		va_end(args);
		fclose(file);
	}
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

	res = p = (char *) malloc(len + 1);

	va_start(argp, n);
	for (i = 0; i < n; i++) {
		arg = va_arg(argp, char *);
		len = strlen(arg);
		strncpy(p, arg, len);
		p += len;
	}
	va_end(argp);

	*p = '\0';

	return res;
}

static void send_ok(int s)
{
	if (send(s, "OK\n", 3, 0) == -1)
		;
		// perror("OK not sent");
}

static void send_err(int s)
{
	if (send(s, "ERR\n", 4, 0) == -1)
		;
		// perror("ERR not sent");
}

static int send_to_user(user *from, user *to, const void *buf, size_t len)
{
	if (send(to->socket, buf, len, 0) == -1) {
		// perror("message send");
		return 0;
	} else 
		return 1;
}

static int send_to_all(user **users, user *from, const void *buf, size_t len) 
{
	user *i;
	int all_good = 1;

	for (i = *users; i != NULL; i = i->next)
		if (from == NULL || from->socket != i->socket)
			if (send(i->socket, buf, len, 0) == -1) {
				// perror("message send");
				all_good = 0;
			}

	return all_good;
}



void strip_nls(char *buf)
{
	char *p = buf + strlen(buf) - 1;

	while (p && (*p == '\r' || *p == '\n'))
		*p-- = '\0';
}

static char *parse_request(int s, char *buf, size_t len, command_t *cmd_set, int *hangup)
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

	while (isspace(*buf))
		buf++;
	
	*cmd_set = NIL;
	if (strncmp(buf, "LOGIN", 5) == 0) {
		*cmd_set = LOGIN;
		buf += 5;
	} if (strncmp(buf, "LOGOUT", 6) == 0) {
		*cmd_set = LOGOUT;
		buf += 6;
	} if (strncmp(buf, "ALL_MSG", 7) == 0) {
		*cmd_set = ALL_MSG;
		buf += 7;
	} if (strncmp(buf, "PRIV_MSG", 8) == 0) {
		*cmd_set = PRIV_MSG;
		buf += 8;
	} if (strncmp(buf, "USERS", 5) == 0) {
		*cmd_set = USERS;
		buf += 5;
	} if (strncmp(buf, "PING", 4) == 0) {
		*cmd_set = PING;
		buf += 4;
	}
	while (isspace(*buf))
		buf++;

	if (*cmd_set != NIL)
		return buf;
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

char *getUsersList(user **users)
{
	user *i;
	int len, buflen;
	char *tmp_buf, *p, *res;

	len = buflen = 0;

	for (i = *users; i != NULL; i = i->next) {
		len ++;
		buflen += strlen(i->name);
		/* Account for a newline between names. */
	}

	tmp_buf = p = (char*) malloc(buflen + len);

	for (i = *users; i != NULL; i = i->next) {
		strcpy(p, i->name);
		p += strlen(i->name);
		*p++ = ' ';
	}
	*(p - 1) = '\0';
	
	res = concatenate(3, "USERS ", tmp_buf, "\n");

	free(tmp_buf);

	return res;
}

int main(int argc, char **argv)
{
	char *port;

	user *users = NULL;
	char buf[MAX_DATA_SIZE + 1];

	socklen_t addrlen;
	struct addrinfo hints, *servinfo, *i;
	struct sockaddr_storage their_addr;

	fd_set master_fds, tmp_fds;
	int maxfd;

	int s;
	int listener_fd, newfd;
	int hangup;
	command_t cmd_set;
		
	pthread_t interactive;

	

	pthread_mutex_init(&terminate_lock, NULL);
	if (pthread_create(&interactive, NULL, interactive_loop, NULL) == -1) {
		fprintf(stderr, "Couldn't initiate interactive mode\n");
		exit(1);
	}
	
		

	// Fixes this: sends crash on SIGPIPE when remote disconnects mid send.
	signal(SIGPIPE, SIG_IGN);

	if (argc == 2)
		port = argv[1];
	else if (argc == 1)
		port = DEFAULT_PORT;
	else 
		fprintf(stderr, "too many arguments.\n");


	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;


	int status;
	if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));	
		exit(1);
	}

	for (i = servinfo; i != NULL; i = i->ai_next) {
		if ((listener_fd = socket(i->ai_family, 
							i->ai_socktype, 
							IPPROTO_TCP)) == -1) {
			perror("socket");
			continue;
		}

		maxfd = listener_fd;

		int yes = 1;
		if (setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, 
						&yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(listener_fd, i->ai_addr, i->ai_addrlen) == -1) {
			close(listener_fd);
			perror("bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (i == NULL) {
		fprintf(stderr, "failed to bind\n");
		exit(2);
	}

	if (listen(listener_fd, BACKLOG) == -1) {
		perror("listen");
		exit(2);
	}


	FD_ZERO(&master_fds);
	FD_SET(listener_fd, &master_fds);

	
	while (1) {
		pthread_mutex_lock(&terminate_lock);
		if (terminated)
			break;
		pthread_mutex_unlock(&terminate_lock);

		// timeout for select set to 2 seconds
		struct timeval tv = {0, 1000};
		tmp_fds = master_fds;
		if (select(maxfd + 1, &tmp_fds, NULL, NULL, &tv) == -1) {
			perror("select");
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
					char *stripped = parse_request(s, buf, sizeof buf - 1, &cmd_set, &hangup);
					if (stripped == NULL) {
						if (hangup) {
							close(s);
							FD_CLR(s, &master_fds);
						} else
							send_err(s);

						break;
					}

					if (cmd_set == LOGIN) {
						char *c = strtok(stripped, " ");
						char *user_name = (char *) malloc(sizeof(char) * (strlen(c) + 1));
						strcpy(user_name, c);

						if (user_name 
							&& strlen(user_name) > 0
							&& get_user(&users, user_name, NULL) == NULL) 
						{
							user_add(&users, user_name, s);
							send_ok(s);
							server_log(s, "%s logged in.\n", user_name);

							char *res = getUsersList(&users);
							send_to_all(&users, NULL, res, strlen(res));
							free(res);

						} else {
							free(user_name);
							send_err(s);
						}
					} else
						send_err(s);
				} else {
					char *stripped = parse_request(s, buf, sizeof buf - 1, &cmd_set, &hangup);

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
								send_ok(s);
								server_log(s, "%s logged out.\n", user_to_logout->name);
								char *res = getUsersList(&users);
								send_to_all(&users, NULL, res, strlen(res));
								free(res);

								free(user_to_logout->name);
								free(user_to_logout);
							} else 
								send_err(s);
							break;


						case PING:
							send_ok(from->socket);
							break;


						case USERS:;
							char *res = getUsersList(&users);
							send_to_user(from, from, res, strlen(res));
							free(res);
							break;


						case ALL_MSG:;
							from_msg = concatenate(5, "ALL_MSG ", from->name, " ", stripped, "\n");
							send_to_all(&users, from, from_msg, strlen(from_msg)); 
							free(from_msg);
							break;


						case PRIV_MSG:;
							char *c = strtok(stripped, " ");						
							if (c == NULL) {
								send_err(from->socket);
								break;
							}

							user *recipient = get_user(&users, c, NULL);
							if (recipient == NULL) {
								send_err(from->socket);
								break;
							}

							c = strtok(NULL, " ");
							if (c == NULL) {
								send_err(from->socket);
								break;
							}
							c[strlen(c)] = ' ';

							from_msg = concatenate(5, "PRIV_MSG ", from->name, " ", c, "\n");

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
