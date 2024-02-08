SOURCE = ldap.cpp decodeLdap.cpp ldapParser.cpp
HEADER = ldap.h decodeLdap.h
OUT = isa-ldapserver
CC = g++
FLAGS = -Wall -Werror -Wextra -std=c++11

# 'default' target
default: $(OUT)

# Rule for building ldap-server
$(OUT): $(SOURCE) $(HEADER)
	$(CC) $(FLAGS) $(SOURCE) -o $(OUT)

# 'clean' target
clean:
	rm -f $(OUT)
