include *.make

#version: debug or release
#optimize: no or yes
ver=debug
opti=no
target=rtpServer.out

STRIP = echo
ifeq ($(ver), debug)
 DEBUGFLAGS = -g
else
 DEBUGFLAGS = -fvisibility=hidden
 STRIP = strip libmedia.so
endif

ifeq ($(opti), no)
 DEBUGFLAGS += -O0
else
 DEBUGFLAGS += -O
endif

#rootDir := $(shell dirname $(readlink -f $0))

#args
CFLAGS 	    = -std=c++0x -std=gnu++0x -fPIC -shared -pipe -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror $(DEBUGFLAGS)

#include dir
IFLAGS      = -I$(libRtmp)

#lib dir
LDFLAGS     =-L$(libRtmp)/librtmp/

LDSTATIC	= -Wl,-Bstatic
LDDYNAMIC	= -Wl,-Bdynamic

#rtmp
LDLIBS      = $(LDSTATIC) -lrtmp
LDLIBS     += $(LDDYNAMIC) -lssl
LDLIBS     += $(LDDYNAMIC) -lcrypto
LDLIBS     += $(LDDYNAMIC) -lz

#common
LDLIBS     += $(LDDYNAMIC) -ldl
LDLIBS     += $(LDDYNAMIC) -lm
LDLIBS     += $(LDDYNAMIC) -lpthread
LDLIBS     += $(LDDYNAMIC) -lrt

#objects after compile
DEP_OBJS    = obj/main.o obj/tcpEngine.o

default:	build

clean:
	rm -rf obj/
	rm -rf *.out

build: createdir $(DEP_OBJS)
	g++ -o $(target) $(DEP_OBJS) $(LDFLAGS) $(LDLIBS)
	$(STRIP)

rebuild: clean build

createdir:
	mkdir -p obj/

obj/main.o: main.cpp
	g++ $(CFLAGS) $(IFLAGS) -c main.cpp -o obj/main.o

obj/tcpEngine.o: TcpEngine.h TcpEngine.cpp
	g++ $(CFLAGS) $(IFLAGS) -c TcpEngine.cpp -o obj/tcpEngine.o

