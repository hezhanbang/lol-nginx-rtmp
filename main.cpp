#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>

#include <librtmp/rtmp_sys.h>
#include <librtmp/log.h>

#include "TcpEngine.h"

struct clientCtx{
	TcpSocket sock;
};

int clientThread(clientCtx* ctx);

int main(){
	printf("starting...\n");

	TcpSocket listenSock;
	listenSock.CreateSocket();
	if(!listenSock.BindLocal(NULL,12345,true)) {
		fprintf(stdout, "cmd listenSock BindLocal fail\n");
		return -1;
	}
	listenSock.MakeListen();

	TcpEngine* listenEngine=new TcpEngine(listenSock,5,-1,true,NULL);

	for(;;){
		SOCKADDR_IN addrClient;
		TcpSocket clientSock=listenEngine->Accept(&addrClient);
		if(!clientSock.IsValidSocket()) {
			continue;
		}

		clientCtx* ctx = new clientCtx();
		ctx->sock = clientSock;
		std::thread thr(&clientThread, ctx);
    	thr.detach();
	}

	return 0;
}

int clientThread(clientCtx* ctx){
	fprintf(stdout, "new client\n");
	return 0;
}
