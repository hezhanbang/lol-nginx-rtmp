#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "TcpEngine.h"

#define SOCKET_ERROR -1
#define INVALID_SOCKET 0
#define SD_SEND SHUT_WR
#define SD_RECEIVE SHUT_RD
#define SD_BOTH SHUT_RDWR
#define closesocket close
#define ZeroMemory(a,b) memset(a,0,b)
#define Sleep(ms) usleep((ms) * 1000)

TcpSocket::TcpSocket()
{
	m_sock=0;
	m_reUseAddr=false;
	m_asyn=false;
}

TcpSocket::~TcpSocket()
{
}

bool TcpSocket::IsValidSocket(SOCKET sock)
{
	if (sock<=0 || INVALID_SOCKET==sock)
	{
		return false;
	}
	return true;
}

bool TcpSocket::IsValidSocket()
{
	return IsValidSocket(m_sock);
}

SOCKET TcpSocket::CreateSocket()
{
	m_sock= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	return m_sock;
}

bool TcpSocket::MakeReUseAddr()
{
	if (!IsValidSocket(m_sock))
	{
		return false;
	}
	int flag=1;
	int len=sizeof(flag);
	if(-1==setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, len))
	{
		return false;
	}
	m_reUseAddr=true;
	return true;
}

bool TcpSocket::MakeAsyn()
{
	if (!IsValidSocket(m_sock))
	{
		return false;
	}

	if(fcntl(m_sock, F_SETFL, O_NONBLOCK)==SOCKET_ERROR){
		char err[255];
		sprintf(err, "fail to set noblock! %d\n", errno);
		return false;
	}

	return true;
}

bool TcpSocket::MakeListen()
{
	if (!IsValidSocket(m_sock))
	{
		return false;
	}
	listen(m_sock,30);
	return true;
}

void TcpSocket::Destroy()
{
	if (!IsValidSocket(m_sock))
	{
		fprintf(stdout,"Is not ValidSocket, m_sock=%d\n",m_sock);
		return;
	}
	closesocket(m_sock);
	fprintf(stdout,"had closed socket, m_sock=%d\n",m_sock);
	m_sock=0;
}

bool TcpSocket::BindLocal(char* localIP, int localport,bool reusePort/*=true*/)
{
	if (reusePort)
	{
		if (!MakeReUseAddr())
		{
			fprintf(stdout,"reuser socket addr fail err=%d\n",errno);
			return false;
		}
	}
	SOCKADDR_IN listenAddr;
	ZeroMemory(&listenAddr,sizeof(listenAddr)); 
	listenAddr.sin_family = AF_INET; 
	listenAddr.sin_port = htons(localport);
	if (localIP)
	{
		listenAddr.sin_addr.s_addr = inet_addr(localIP);
	}
	else
	{
		listenAddr.sin_addr.s_addr = INADDR_ANY;
	}

	int nbind = bind(m_sock,(SOCKADDR *)&listenAddr,sizeof(SOCKADDR)); 
	if (SOCKET_ERROR==nbind) 
	{ 
		int err=errno;
		closesocket(m_sock);
		m_sock=0;
		fprintf(stdout, "bind fail err=%d\n",err);
		return false; 
	}
	return true;
}

TcpEngine::TcpEngine(TcpSocket clientSock, int sendAndRecvTimeout, int connectTimeout, 
	bool bAutoFreeSocket/* =true */,bool* continueDo/* =nullptr */)
{
	this->m_lastError=0;
	this->m_socket=clientSock;
	this->m_bAutoFreeSocket=bAutoFreeSocket;
	this->m_sendAndRecvTimeout=sendAndRecvTimeout;
	this->m_connectTimeout=connectTimeout;
	this->m_continuDo=continueDo;

	if (!this->m_socket.IsValidSocket())
	{
		return;
	}
	this->m_socket.MakeAsyn();
}

TcpEngine::~TcpEngine(void)
{
	if (this->m_bAutoFreeSocket)
	{
		m_socket.Destroy();
	}
}

int TcpEngine::Recv(char* buf,int len)
{
	if (!m_socket.IsValidSocket())
	{
		return -1;
	}
	time_t start=time(NULL);
	int ret=-1;
	fd_set fsetread;

	for (;nullptr==m_continuDo || true==*m_continuDo;)
	{
		struct timeval tv;
		tv.tv_sec=0;
		tv.tv_usec=20 * 1000;

		FD_ZERO(&fsetread);
		FD_SET(m_socket.GetSocket(), &fsetread);
		time_t end=time(NULL);
		ret=select(m_socket.GetSocket()+1,&fsetread,NULL,NULL, &tv);
		if (ret>0)
		{
			break;
		}

		if (m_sendAndRecvTimeout>0)
		{
			if (end-start>m_sendAndRecvTimeout)
			{
				break;
			}
		}
	}

	if (ret<=0)
	{
		return -2;
	}

	ret = recv(m_socket.GetSocket(), buf, len, 0); 
	return ret;
}

int TcpEngine::Send(char* buf,int len)
{
	if (!m_socket.IsValidSocket())
	{
		return -1;
	}
	time_t start=time(NULL);
	int ret=-1;
	fd_set fsetwrite;

	for (;nullptr==m_continuDo || true==*m_continuDo;)
	{
		struct timeval tv;
		tv.tv_sec=0;
		tv.tv_usec=20 * 1000;

		FD_ZERO(&fsetwrite);
		FD_SET(m_socket.GetSocket(), &fsetwrite);
		time_t end=time(NULL);
		ret=select(m_socket.GetSocket()+1,NULL,&fsetwrite,NULL, &tv);
		if (ret>0)
		{
			break;
		}

		if (m_sendAndRecvTimeout>0)
		{
			if (end-start>m_sendAndRecvTimeout)
			{
				break;
			}
		}
	}

	if (ret<=0)
	{
		return -2;
	}

	ret = send(m_socket.GetSocket(), buf, len, 0);
	if (ret<=0)
	{
		fprintf(stdout,"send fail, ret=%d, err=%d\n",ret,errno);
	}
	return ret;
}

int TcpEngine::Send(char* str)
{
	return SendAllBuf(str,strlen(str));
}

int TcpEngine::SendAllBuf(char* str,int totalLen)
{
	int hadSent=0;
	int eachSent=0;

	if (totalLen<=0)
	{
		return 0;
	}
	while (hadSent<totalLen)
	{
		eachSent=this->Send(str+hadSent,totalLen-hadSent);
		if (eachSent<=0)
		{
			return -1;
		}
		hadSent+=eachSent;
	}
	return totalLen;
}

int TcpEngine::Close(Direction dire)
{
	if (!m_socket.IsValidSocket())
	{
		return 0;
	}
	Sleep(100);
	if (send_dire==dire)
	{
		shutdown(this->m_socket.GetSocket(),SD_SEND);
	}
	else if (recv_dire==dire)
	{
		shutdown(this->m_socket.GetSocket(),SD_RECEIVE);
	}
	else if (closeSocket_dire==dire)
	{
		this->m_socket.Destroy();
	}
	return 0;
}

TcpSocket TcpEngine::Accept(SOCKADDR_IN* addr)
{
	if (!m_socket.IsValidSocket() || (m_continuDo && false==*m_continuDo ))
	{
		TcpSocket newSock;
		return newSock;
	}
	int ret=-1;
#ifdef WIN32
	int len=sizeof(SOCKADDR_IN);
#else
	socklen_t len=sizeof(SOCKADDR_IN);
#endif
	SOCKADDR_IN addrClient;
	fd_set fsetread;

	#define TCP_ACCEPT_TIMEOUT_USEC 500*1000 //接受一个新socket的间隔，一百万分之一秒，微秒

	struct timeval tv;
	tv.tv_sec=0;
	tv.tv_usec=TCP_ACCEPT_TIMEOUT_USEC;

	FD_ZERO(&fsetread);
	FD_SET(m_socket.GetSocket(), &fsetread);
	ret=select(m_socket.GetSocket()+1,&fsetread,NULL,NULL, &tv);
	if (ret<=0)
	{
		if(ret<0)
		{
			int err=errno;
			fprintf(stdout, "err=%d\n",err);
		}
		TcpSocket newSock;
		return newSock;
	}
	SOCKET clientSock=accept(m_socket.GetSocket(),(sockaddr*)&addrClient,&len);
	if (clientSock<=0)
	{
		TcpSocket newSock;
		return newSock;
	}
	if (addr)
	{
		*addr=addrClient;
	}
	TcpSocket client;
	client.m_sock=clientSock;
	return client;
}

int TcpEngine::Connect(char* ip,int port)
{
	if (!m_socket.IsValidSocket())
	{
		return -1;
	}
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family          = PF_INET;
	sin.sin_port            = htons((u_short) port);
	sin.sin_addr.s_addr     = inet_addr(ip);

	int reVal = connect(this->m_socket.GetSocket(), (struct sockaddr *)&sin, sizeof(sin));

	if (reVal == 0)
	{
		return 0;
	}

	int currentTimes=0;
	int ret=-1;
	fd_set fsetwrite;
	for (;nullptr==m_continuDo || true==*m_continuDo;)
	{
		struct timeval tv;
		tv.tv_sec=0;
		tv.tv_usec=900 * 1000;

		FD_ZERO(&fsetwrite);
		FD_SET(m_socket.GetSocket(), &fsetwrite);
		ret=select(m_socket.GetSocket()+1,NULL,&fsetwrite,NULL, &tv);
		if (ret>0)
		{
			break;
		}

		if (m_connectTimeout>0)
		{
			currentTimes++;
			if (currentTimes>=m_connectTimeout)
			{
				break;
			}
		}
	}

	if (ret<=0)
	{
		return -2;
	}

	if (FD_ISSET(m_socket.GetSocket(), &fsetwrite))
	{
		int error       = 0;
		socklen_t len   = sizeof(error);
		getsockopt(m_socket.GetSocket(), SOL_SOCKET, SO_ERROR, (char *)&error, &len);

		if (error == 0)
		{
			return 0;
		}

		return -3;
	}

	return -4;
}