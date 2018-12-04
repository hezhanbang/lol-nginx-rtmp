#ifndef __TCP_ENGINE_H__
#define __TCP_ENGINE_H__

#include <ifaddrs.h>
#include <netinet/in.h>  
#include <sys/ioctl.h>
#include <sys/socket.h>  
#include <sys/stat.h>
#include <sys/types.h>  

#define SOCKET int
#define SOCKADDR sockaddr
#define SOCKADDR_IN sockaddr_in

class TcpSocket
{
public:
	friend class TcpEngine;

	TcpSocket();
	virtual ~TcpSocket();
	static bool IsValidSocket(SOCKET sock);

	bool IsValidSocket();
	SOCKET CreateSocket();
	bool MakeReUseAddr();
	bool MakeAsyn();
	bool MakeListen();
	void Destroy();
	bool BindLocal(char* localIP, int localport,bool reusePort=true);

	bool IsReUseAddr(){return m_reUseAddr;}
	bool IsAsyn(){return m_asyn;}
	SOCKET GetSocket(){return m_sock;}

private:
	SOCKET m_sock;
	bool m_reUseAddr;
	bool m_asyn;
};

enum Direction
{
	send_dire,
	recv_dire,
	closeSocket_dire,
};

class TcpEngine
{
public:
	TcpEngine(TcpSocket clientSock, int sendAndRecvTimeout, int connectTimeout, 
		bool bAutoFreeSocket=true,bool* continueDo=nullptr);
	virtual ~TcpEngine(void);

	TcpSocket Accept(SOCKADDR_IN* addr);
	int Connect(char* ip,int port);

	virtual int Recv(char* buf,int len);
	virtual int Send(char* buf,int len);
	virtual int SendAllBuf(char* str,int totalLen);
	virtual int Send(char* str);
	virtual int Close(Direction dire=closeSocket_dire);
	TcpSocket GetSocket(){return m_socket;}
	int GetLastError(){return m_lastError;}

protected:
	TcpSocket m_socket;
	bool m_bAutoFreeSocket;
	bool* m_continuDo;
	int m_sendAndRecvTimeout;
	int m_connectTimeout;
	int m_lastError;
};

#endif