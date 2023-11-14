# Made by: Timotej Bucka (xbucka00)

CC=g++
CFLAGS=-Wall -Wextra -pedantic -std=c++11 -lncurses -lpcap
NAME=dhcp-stats

dhcp-stats: $(NAME).cpp IPPrefix.cpp
	$(CC) $(NAME).cpp IPPrefix.cpp -o $(NAME) $(CFLAGS)

clean:
	rm -f $(NAME)
