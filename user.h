#ifndef USER_H
#define USER_H

struct _user {
	char *name;
	int socket;
	
	struct _user *next;
};

typedef struct _user user;


int user_add(user **u, const char *name, int socket);
user *user_get(user **u, const char *name);
char *user_get_all(user **u);
int user_rm(user **u, const char *name);
int user_rm_all(user **u);

#endif
