#version: debug or release
#optimize: no or yes
ver=debug
opti=no
libRtmp= ./doc/rtmpdump-2.3
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

#uuid
LDLIBS      = $(LDSTATIC) -lrtmp

#common
LDLIBS     += $(LDDYNAMIC) -ldl
LDLIBS     += $(LDDYNAMIC) -lm
LDLIBS     += $(LDDYNAMIC) -lpthread
LDLIBS     += $(LDDYNAMIC) -lrt

#objects after compile
DEP_OBJS    = obj/main.o

default:	build

clean:
	rm -rf obj/
	rm -rf *.out

build: createdir $(DEP_OBJS) $(target)
	g++ -o $(target) $(DEP_OBJS) $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	$(STRIP)

rebuild: clean build

createdir:
	mkdir -p obj/

obj/main.o: CriticalSection.cpp
	g++ $(CFLAGS) $(IFLAGS) -c main.cpp -o obj/main.o
