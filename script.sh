#! /bin/bash

if [ -e p ]
then
	rm p
fi
mkfifo p

printf "LOGIN gusta\r\n" > p
printf "ALL_MSG fongujeto?\r\n" > p
printf "ALL_MSG rororo\r\n" > p
