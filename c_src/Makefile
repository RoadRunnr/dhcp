CFLAGS +=-std=gnu99 -Wall -Werror -fPIC -I. $(shell erl -noinput -eval 'io:format("-I~s -I~s/erts-~s/include", [code:lib_dir(erl_interface, include), code:root_dir(), erlang:system_info(version)]), halt(0).')
LDFLAGS +=-shared $(shell erl -noinput -eval 'io:format("-L~s", [code:lib_dir(erl_interface, lib)]), halt(0).')

all : ../priv/dhcp_udp_server.so

../priv/dhcp_udp_server.so : dhcp_udp_server.o
	(test -d ../priv || mkdir -p ../priv)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f ../priv/dhcp_udp_server.so dhcp_udp_server.o

