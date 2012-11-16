#ifndef USER_H
#define USER_H

struct _user {
	char *name;
	int socket;
	
	struct _user *next;
};

typedef struct _user user;


int user_add(user **u, const char *name, int socket);
user *get_user_by_name(user **u, const char *name);
user *get_user_by_socket(user **u, int s);
char *get_all_users(user **u);
int user_rm(user **u, const char *name);
int user_rm_all(user **u);

#endif
