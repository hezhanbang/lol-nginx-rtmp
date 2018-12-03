#include <stdio.h>
#include <string.h>

#include "librtmp/rtmp_sys.h"
#include "librtmp/log.h"

int main(){
	printf("hello\n");

	RTMP *rtmp=RTMP_Alloc();
	RTMP_Init(rtmp);
	//set connection timeout,default 30s
	rtmp->Link.timeout=10;	


	return 0;
}