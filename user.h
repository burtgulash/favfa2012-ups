#ifndef USER_H
#define USER_H
// #include <netinet/in.h>
#include <arpa/inet.h>

struct _user {
	char *name;
	int socket;
	
	struct _user *next;
};

typedef struct _user user;


int user_add(user **u, const char *name, int socket);
user *user_rm(user **u, const char *name, int *s);
user *get_user(user **u, const char *name, int *s);
char *get_all_users(user **u);
int user_rm_all(user **u);

#endif
