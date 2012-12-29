#include <stdlib.h>
#include <string.h>

#include "user.h"

extern pthread_mutex_t users_lock;

int user_add(user **u, const char *name, int socket)
{
	user *new = (user*) malloc(sizeof(user));
	new->name = (char*) malloc(strlen(name) + 1);
	strcpy(new->name, name);
	new->socket = socket;

	pthread_mutex_lock(&users_lock);
	new->next = *u;
	*u = new;
	pthread_mutex_unlock(&users_lock);


	return 1;
}

user *get_user(user **u, const char *name, int *s)
{
	user *i;

	pthread_mutex_lock(&users_lock);
	for (i = *u; i != NULL; i = i->next)
		if ((s || name) 
				&& (!s    || *s == i->socket) 
				&& (!name || strcmp(i->name, name) == 0)) {
			pthread_mutex_unlock(&users_lock);
			return i;
		}
	pthread_mutex_unlock(&users_lock);
	
	return NULL;
}


user *user_rm(user **u, const char *name, int *s)
{
	user *i, *prev;

	prev = NULL;

	pthread_mutex_lock(&users_lock);
	for (i = *u; i != NULL; i = i->next) {
		if ((s || name) 
				&& (!s    || *s == i->socket) 
				&& (!name || strcmp(i->name, name) == 0)) 
		{
			if (prev)
				prev->next = i->next;
			else
				*u = i->next;

			i->next = NULL;
	
			pthread_mutex_unlock(&users_lock);
			return i;
		}
		
		prev = i;
	}
	pthread_mutex_unlock(&users_lock);
	
	return NULL;
}

int user_rm_all(user **u)
{
	user *i, *next;

	pthread_mutex_lock(&users_lock);
	for (i = *u; i != NULL; i = next) {
		next = i->next;
		free(i->name);
		free(i);
	}

	*u = NULL;
	pthread_mutex_unlock(&users_lock);

	return 1;
}
