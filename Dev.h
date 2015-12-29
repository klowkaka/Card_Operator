int __stdcall Dev_Init(int Port, unsigned long baud);
int __stdcall Dev_exit(HANDLE icdev);
int __stdcall Dev_card(HANDLE icdev,unsigned char Mode,unsigned long *Snr);
int __stdcall Dev_authentication_pass_hex(HANDLE icdev, unsigned char Mode, unsigned char Addr, unsigned char *passbuff);
int __stdcall Dev_read_hex(HANDLE icdev,unsigned char Adr,unsigned char *Data);
int __stdcall Dev_write_hex(HANDLE icdev,unsigned char Adr,unsigned char *Data);
int __stdcall Dev_initval(HANDLE icdev,unsigned char Adr,unsigned long Value);
int __stdcall Dev_readval(HANDLE icdev,unsigned char Adr,unsigned long *Value);
int __stdcall Dev_increment(HANDLE icdev,unsigned char Adr,unsigned long Value);
int __stdcall Dev_decrement(HANDLE icdev,unsigned char Adr,unsigned long Value);
int __stdcall Dev_restore(HANDLE icdev,unsigned char Adr);
int __stdcall Dev_transfer(HANDLE icdev,unsigned char Adr);
int __stdcall Dev_halt(HANDLE icdev);
int __stdcall Dev_beep(HANDLE icdev,unsigned int Msec);
int __stdcall Dev_cpureset(HANDLE icdev,unsigned char cardtype,unsigned char baudrate,
							   unsigned char Volt,unsigned char *databuffer);
int __stdcall Dev_cpuapdu(HANDLE icdev,unsigned char cardtype,unsigned char slen,unsigned char * sendbuffer,
							  unsigned char * databuffer);
int __stdcall Dev_readinfo(HANDLE icdev, char *name, char *sex, char *nation, char *birth, 
								   char *address, char *number, char *department, char *validdate);
int __stdcall Dev_authentication_pass(HANDLE icdev, unsigned char Mode, unsigned char Addr, unsigned char *passbuff);
int __stdcall Dev_read(HANDLE icdev,unsigned char Adr,unsigned char *Data);
int __stdcall Dev_write(HANDLE icdev,unsigned char Adr,unsigned char *Data);