#include <stdlib.h>
#include <string.h>

#include "user.h"

int user_add(user **u, const char *name, int socket)
{
	user *new = (user*) malloc(sizeof(user));
	new->name = (char*) malloc(strlen(name) + 1);
	strcpy(new->name, name);
	new->socket = socket;

	new->next = *u;
	*u = new;


	return 1;
}

user *get_user(user **u, const char *name, int *s)
{
	user *i;

	for (i = *u; i != NULL; i = i->next)
		if ((s || name) 
				&& (!s    || *s == i->socket) 
				&& (!name || strcmp(i->name, name) == 0)) 
			return i;
	
	return NULL;
}

char *get_all_users(user **u)
{
	user *i;
	int len, buflen;
	char *buf, *tmp;

	len = buflen = 0;

	for (i = *u; i != NULL; i = i->next) {
		len ++;
		buflen += strlen(i->name);

		/* Account for a space between names. */
		if (len > 1)
			buflen ++;
	}

	buf = tmp = (char*) malloc(buflen + 1);

	for (i = *u; i != NULL; i = i->next) {
		strcpy(tmp, i->name);
		tmp += strlen(i->name);
		*tmp++ = ' ';
	}
	*tmp = '\0';

	return buf;
}

user *user_rm(user **u, const char *name, int *s)
{
	user *i, *prev;

	prev = NULL;

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
	
			return i;
		}
		
		prev = i;
	}
	
	return NULL;
}

int user_rm_all(user **u)
{
	user *i, *next;

	for (i = *u; i != NULL; i = next) {
		next = i->next;
		free(i->name);
		free(i);
	}

	*u = NULL;

	return 1;
}
