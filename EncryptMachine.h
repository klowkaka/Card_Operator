#ifndef _ICCENCRYPTMACHINE_H_
#define _ICCENCRYPTMACHINE_H_
	int STDMETHODCALLTYPE miclient (char *i_Addr, unsigned long i_Port, unsigned long TimeOut, 
			  char *DataOut, unsigned int LenOut, 
			  char *DataIn, unsigned int LenIn);
	int STDMETHODCALLTYPE Send_Machine(unsigned char *Hostaddr, unsigned long Hostport, long HOST_TIMEOUT, int Inlen, 
									   unsigned char *Indata,int Outlen,unsigned char *Outdata);

#endif