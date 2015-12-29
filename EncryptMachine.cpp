#include "stdafx.h"
#include "public.h"
#include "dev_error.h"
#include "winsock.h"
#include "sys/types.h"

int STDMETHODCALLTYPE miclient (char *i_Addr, unsigned long i_Port, unsigned long TimeOut, 
			  char *DataOut, unsigned int LenOut, 
			  char *DataIn, unsigned int LenIn)
{
/***************************************************************************
parameters:	
	i_addr:	IP address of host
	i_port:	socket port of host
	dataout: data to send
	lenout: length of data to send
	datain: data to receive
	lenin: length of data to receive
return:
	len received
	-1 if failed
****************************************************************************/
	WSADATA ws;
	SOCKET s;
	struct sockaddr_in Addr;
	char Buff[512];
	int ReadCount;
	unsigned long LastTick;

	if ((LenOut > 256) ||(LenIn > 256))
		return -8001;

	if (WSAStartup (0x0202, &ws))
		return -8002;

	s = socket (AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return -8003;
	
	Addr.sin_family = AF_INET;
	Addr.sin_port = htons (i_Port);				//host port
	Addr.sin_addr.s_addr = inet_addr (i_Addr);	//host ip address
	if (connect (s, (struct sockaddr *) &Addr, sizeof (Addr)) == SOCKET_ERROR)
	{	// connect failed
		closesocket (s);
		WSACleanup();
		return -8004;
	}
	
	//==================================================================
	// sending
	if (LenOut > 0)		//data to output?
	{
		if (!send (s, DataOut, LenOut, 0))
		{
			closesocket (s);
			WSACleanup ();
			return -8005;
		}
	}
	
	//==================================================================
	// reading
	ReadCount = 0;
	if (LenIn > 0)		//data to input?
	{
		memset (Buff, 0, 500);	//ini buffer
		LastTick = GetTickCount();
		do
		{
			ReadCount = recv (s, Buff, LenIn, 0);
			if (ReadCount > 0)
			{
				memcpy (DataIn, Buff, LenIn);
				closesocket (s);
				WSACleanup ();
				return (ReadCount);
			}
		}while (GetTickCount() - LastTick < TimeOut);
	}

	closesocket (s);
	WSACleanup ();
	return -8006;	//time out
}

int STDMETHODCALLTYPE Send_Machine(unsigned char *Hostaddr, unsigned long Hostport, long HOST_TIMEOUT, int Inlen, 
									   unsigned char *Indata,int Outlen,unsigned char *Outdata)
/*********************************************************************
函数说明：往加密机中发送指令。
输入值：  Inlen,数据的数据长度
		  Indata,输入的数据
		  Outlen,接收数据长度
输出值：  Outdata,加密机返回的数据
返回值：  =0表示成功；
		  <0表示失败。
***********************************************************************/
{
	int ret;
	char Inbuff[500],Outbuff[500];
	char temp[10];

	memset(Inbuff, 0x00, sizeof(Inbuff));
	memset(Outbuff, 0x00, sizeof(Outbuff));
	LongValue_Hex(Inlen, 2, (unsigned char *)Inbuff);//长度
	memcpy(Inbuff+2, Indata, Inlen);//消息内容	
	ret=miclient((char *)Hostaddr, Hostport, HOST_TIMEOUT, Inbuff, Inlen+2, Outbuff, Outlen);
	if (ret<0)
		return Dev_RemoteMachineErr;
	if (memcmp(Outbuff+4, "00", 2) !=0)
	{
		memset(temp, 0x00, sizeof(temp));
		memcpy(temp, "1", 1);
		memcpy(temp+1, Outbuff+4, 2);
		return -atoi(temp);
	}
	memcpy(Outdata, Outbuff+6, Outlen-4);
	return 0;
}