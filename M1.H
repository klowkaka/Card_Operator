#ifndef _M1_H_
#define _M1_H_

int STDMETHODCALLTYPE M1_Write(int icdev, int addr, unsigned char *data);
int STDMETHODCALLTYPE OpenSession(int Port, unsigned char *Csn);
int STDMETHODCALLTYPE CloseSession(void);
int STDMETHODCALLTYPE ReadVerify(unsigned char *Key, unsigned char *Outstr);
int STDMETHODCALLTYPE ComputerKey(int KeyId, unsigned char *Instr, unsigned char *Outstr);
int STDMETHODCALLTYPE JugeErrorPoint(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ReadPersonInfo(int Keymode, int Secno, unsigned char *Key, unsigned char *PersonInfo);
int STDMETHODCALLTYPE ResumeA(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeBorC(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeB1(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeB2(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeD(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeE(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE ResumeF(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon);
int STDMETHODCALLTYPE GetValue(int Keymode, int Secno, unsigned char *Key, unsigned long *MoneyValue);
int STDMETHODCALLTYPE WriteTradeOriginalA(int Keymode, int Secno, unsigned char *Key, 
											  unsigned long *Totalcount,unsigned long *Index);
int STDMETHODCALLTYPE WriteTradeOriginalB(int Keymode, int Secno, unsigned char *Key);
int STDMETHODCALLTYPE IncMoneyOriginal (int Keymode, int Secno, unsigned char *Key, 
											unsigned long OldMoney, unsigned long LoadMoney);
int STDMETHODCALLTYPE WriteAddRecord (int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
										 unsigned long OldMoney, unsigned long LoadMoney, 
										 unsigned char *Adddate, unsigned char *Addtime);
int STDMETHODCALLTYPE WriteRecord(int Keymode, unsigned char *Key, unsigned long Index, unsigned char *Date,
									 unsigned char *Time, unsigned long oldmoney, unsigned long Trademoney, 
									 unsigned char *TradeType);
int STDMETHODCALLTYPE CopyTrade(int Keymode, int Secno, unsigned char *Key);
int STDMETHODCALLTYPE CopyMoney(int Keymode, int Secno, unsigned char *Key);
int STDMETHODCALLTYPE DecMoneyOriginal (int Keymode, int Secno, unsigned char *Key, 
											unsigned long OldMoney, unsigned long PurchaseMoney);
int STDMETHODCALLTYPE M_1001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData);
int STDMETHODCALLTYPE M_2001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData);
int STDMETHODCALLTYPE M_3001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData);
int STDMETHODCALLTYPE M_4001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData);
#endif