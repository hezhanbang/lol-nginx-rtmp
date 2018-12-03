#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"

int main(){
	printf("hello\n");

	FILE *fp=fopen("receive.flv","wb");
	if (!fp){
		RTMP_LogPrintf("Open File Error.\n");
		return -1;
	}

	/* set log level */
	RTMP_LogLevel loglvl=RTMP_LOGDEBUG;
	RTMP_LogSetLevel(loglvl);

	int nRead;
	int bufsize=1024*1024*10;			
	char *buf=(char*)malloc(bufsize);
	memset(buf,0,bufsize);
	long countbufsize=0;

	RTMP *rtmp=RTMP_Alloc();
	RTMP_Init(rtmp);
	//set connection timeout,default 30s
	rtmp->Link.timeout=10;	


	if(!RTMP_SetupURL(rtmp, (char*)"rtmp://192.168.1.151/myapp/mystream"))
	{
		RTMP_Log(RTMP_LOGERROR,"SetupURL Err\n");
		RTMP_Free(rtmp);
		return -1;
	}
	rtmp->Link.lFlags|=RTMP_LF_LIVE;
	//1hour
	RTMP_SetBufferMS(rtmp, 3600*1000);		
	
	if(!RTMP_Connect(rtmp,NULL)){
		RTMP_Log(RTMP_LOGERROR,"Connect Err\n");
		RTMP_Free(rtmp);
		return -1;
	}
 
	if(!RTMP_ConnectStream(rtmp,0)){
		RTMP_Log(RTMP_LOGERROR,"ConnectStream Err\n");
		RTMP_Close(rtmp);
		RTMP_Free(rtmp);
		return -1;
	}
 
	for(;;){
		nRead=RTMP_Read(rtmp,buf,bufsize);
		if(nRead<=0){
			break;
		}
		fwrite(buf,1,nRead,fp);
 
		countbufsize+=nRead;
		RTMP_LogPrintf("Receive: %5dByte, Total: %5.2fkB\n",nRead,countbufsize*1.0/1024);
	}

	return 0;
}