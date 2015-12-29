#include "stdafx.h"
#include "stdio.h"
#include <stdlib.h>
#include "dev.h"
#include "M1.h"
#include "dev_error.h"
#include "public.h"

extern int icdev;
extern char *MAINKEY;

int STDMETHODCALLTYPE M1_Write(int icdev, int addr, unsigned char *data)
{
	int ret;
	unsigned char read_data[33];

	ret=Dev_write_hex((HANDLE)icdev, addr, data);
	if (ret < 0)
		return Dev_WriteErr;

	ret=Dev_read_hex((HANDLE)icdev, addr, read_data);
	if (ret < 0)
		return Dev_ReadErr;
	if (memicmp(data, read_data, 32) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE OpenSession(int Port, unsigned char *Csn)
/********************************************************************************
说明：连接卡机和选择卡片,读取0扇区的数据,准备下一步的卡操作
输入: Port，端口号

输出: Csn，卡片序列号
返回:
	 =0   表示成功
     <0   表示失败
********************************************************************************/
{
	int ret;
	unsigned char buff[100], read_str[33],key[13];
	unsigned long snr=0;

	memset(buff, 0x00, sizeof(buff));
	memset(key, 0x00, sizeof(key));
	memset(read_str, 0x00, sizeof(read_str));

	
	//打开端口
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;

	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snr);
	if (ret != 0)
		return Dev_CardSearchErr;

	//下载0扇区KeyA密码
	memcpy(key, "\xA0\xA1\xA2\xA3\xA4\xA5", 12);
	//验证0扇区keyA密码
	ret = Dev_authentication_pass((HANDLE)icdev, 0, 0, key);
	if (ret != 0)
		return Dev_AuthErr;

	//读0扇区0块
	ret = Dev_read((HANDLE)icdev, 0*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(Csn, read_str, 4);//卡片序列号
	
	return 0;
}

int STDMETHODCALLTYPE CloseSession(void)
/********************************************************************************
说明：关闭读卡器
输入: 无

输出: 无
返回:
	 =0   表示成功
     <0   表示失败
********************************************************************************/
{
	int ret;

	//中止操作
	ret = Dev_halt((HANDLE)icdev);
	if (ret != 0)
		return Dev_HaltErr;
	Dev_beep((HANDLE)icdev, 20);
	Dev_exit((HANDLE)icdev);
	icdev = 0;
	return 0;
}

int STDMETHODCALLTYPE ReadVerify(unsigned char *Key, unsigned char *Outstr)
/********************************************************************************
说明：读取1扇区发行区并判断合法性
输入: Key,密钥

输出: Outstr,返回的1扇区信息
返回:
	 =0   表示成功
     <0   表示失败
********************************************************************************/
{
	int ret;
	unsigned char read_str[33];
	unsigned char cardcrc[3],cardcrc_hex[3];

	memset(read_str, 0x00, sizeof(read_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	memset(cardcrc_hex, 0x00, sizeof(cardcrc_hex));

	//验证1扇区keya密码
	ret = Dev_authentication_pass((HANDLE)icdev, 0, 1, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读1扇区0块
	ret = Dev_read((HANDLE)icdev, 1*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	//判断校验位是否正确
	Computer_Crc(read_str, cardcrc, 15);
	Asc_Hex(cardcrc, 1, cardcrc_hex);
	if (memcmp(read_str+15, cardcrc_hex, 1) !=0)
		return Dev_CheckErr;
	memcpy(Outstr, read_str, 14);//城市代码，应用代码，发行流水号，启用标志，卡类别
	//读1扇区1块
	ret = Dev_read((HANDLE)icdev, 1*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	//判断校验位是否正确
	Computer_Crc(read_str, cardcrc, 15);
	Asc_Hex(cardcrc, 1, cardcrc_hex);
	if (memcmp(read_str+15, cardcrc_hex, 1) !=0)
		return Dev_CheckErr;
	memcpy(Outstr+14, read_str, 14);//发行日期,有效日期，启用日期，押金
	return 0;
}

int STDMETHODCALLTYPE ComputerKey(int KeyId, unsigned char *Instr, unsigned char *Outstr)
/********************************************************************************
说明：计算扇区密码
输入: KeyId, 0-KeyA，1-KeyB
	  Instr, 输入的计算扇区密码的字符串(4位卡片序列号+2发行流水号后2位+1位卡片认证码+扇区标识)
输出: Outstr,输出的扇区密码
返回:
	 =0   表示成功
     <0   表示失败
********************************************************************************/
{
	if (KeyId == 0)//KeyA
	{
		Triple3DES(Instr, (unsigned char *)MAINKEY, Outstr);
	}
	if (KeyId == 1)//KeyB
	{
		Triple3DES(Instr, (unsigned char *)MAINKEY, Outstr);
	}			
	return 0;
}

int STDMETHODCALLTYPE JugeErrorPoint(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：判断M1卡片恢复出错点
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno1, 钱包扇区
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区
	  Key2, 公共扇区密码
输出: OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
返回:
	 =0  表示正常
     1   A段出错
	 2	 B或C段出错
	 3   B1段出错
	 4   B2段出错
	 5   D段出错
	 6   E段出错
	 7   F段出错
	 <0  表示错误
********************************************************************************/
{
	int ret,OriginalMoneyFlag=0,CopyMoneyFlag=0,OriginalCommonFlag=0,CopyCommonFlag=0;
	unsigned long OriginalMoneyValue=0,CopyMoneyValue=0,Originaltotalcount=0,Copytotalcount=0;
	unsigned char OriginalCommonStr[33],CopyCommonStr[33], OriginalCommonStrXor[33],CopyCommonStrXor[33];
	unsigned char cardcrc[3],cardcrc_hex[3];
	

	memset(OriginalCommonStr, 0x00, sizeof(OriginalCommonStr));
	memset(CopyCommonStr, 0x00, sizeof(CopyCommonStr));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	memset(cardcrc_hex, 0x00, sizeof(cardcrc_hex));
	memset(OriginalCommonStrXor, 0x00, sizeof(OriginalCommonStrXor));
	memset(CopyCommonStrXor, 0x00, sizeof(CopyCommonStrXor));
	/***************************
	 读取钱包正副本信息扇区
	****************************/
	//验证钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//读钱包正本扇区1块
	ret = Dev_readval((HANDLE)icdev, Secno1*4+1, &OriginalMoneyValue);
	if (ret != 0)
		OriginalMoneyFlag=1;//非法
	else
	{
		OriginalMoneyFlag=0;//合法
		sprintf((char *)OriginalMoney, "%012u", OriginalMoneyValue);
	}
	//读钱包副本扇区2块
	ret = Dev_readval((HANDLE)icdev, Secno1*4+2, &CopyMoneyValue);
	if (ret != 0)
		CopyMoneyFlag=1;//非法
	else
	{
		CopyMoneyFlag=0;//合法
		sprintf((char *)CopyMoney, "%012u", CopyMoneyValue);
	}

	/***************************
	 读取公共信息区正副本信息扇区
	****************************/
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//读公共信息区正本扇区0块
	ret = Dev_read((HANDLE)icdev, Secno2*4+0, OriginalCommonStr);
	if (ret != 0)
		return Dev_ReadErr;
	Computer_Crc(OriginalCommonStr, cardcrc, 15);
	Asc_Hex(cardcrc, 1, cardcrc_hex);
	if (memcmp(OriginalCommonStr+15, cardcrc_hex, 1) !=0)
		OriginalCommonFlag=1;//非法
	else
	{
		OriginalCommonFlag=0;//合法
		memcpy(OriginalCommon, OriginalCommonStr, 16);
		Originaltotalcount = Hex_LongValue(OriginalCommonStr+1, 2);//正本钱包累计交易次数
		memcpy(OriginalCommonStrXor, OriginalCommonStr, 8);
	}
	//读公共信息区副本扇区1块
	ret = Dev_read((HANDLE)icdev, Secno2*4+1, CopyCommonStr);
	if (ret != 0)
		return Dev_ReadErr;
	Computer_Crc(CopyCommonStr, cardcrc, 15);
	Asc_Hex(cardcrc, 1, cardcrc_hex);
	if (memcmp(CopyCommonStr+15, cardcrc_hex, 1) !=0)
		CopyCommonFlag=1;//非法
	else
	{
		CopyCommonFlag=0;//合法
		memcpy(CopyCommon, CopyCommonStr, 16);
		memcpy(CopyCommonStrXor, CopyCommonStr, 8);
		Copytotalcount = Hex_LongValue(CopyCommonStrXor+1, 2);//副本钱包累计交易次数
	}

	/***************************
	 出错点判断
	****************************/
	//正常交易
	if ((OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) && (OriginalCommonFlag == 0) && (CopyCommonFlag == 0)
		&& (memcmp(OriginalCommonStr+3, "\x02", 1) == 0) && (memcmp(OriginalCommonStrXor, CopyCommonStr, 8) == 0) &&
		(OriginalMoneyValue == CopyMoneyValue))
		return 0;
	/********************************************
	   A段出错
	   第一种情况
	   1.	公共信息区正本=非法
	   2.	钱包正本=副本
	   第二种情况
	   1.	正本交易进程标志="01"
	   2.	钱包正本=副本
	*********************************************/
	if (((OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) && (OriginalMoneyValue == CopyMoneyValue) && (OriginalCommonFlag==1)) ||
        ((OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) && (OriginalMoneyValue == CopyMoneyValue) && 
		(memcmp(OriginalCommonStr+3, "\x01", 1) == 0) && (Originaltotalcount == Copytotalcount)))
		return 1;
	/********************************************
	   B或C段出错
	   1.	正本交易过程标志="01"
       2.	正本钱包累计交易次数-1=副本
       3.	钱包正本<副本
	*********************************************/
	if ((memcmp(OriginalCommonStr+3, "\x01", 1) == 0) && ((Originaltotalcount -1) == Copytotalcount) && 
		(OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) && (OriginalMoneyValue < CopyMoneyValue))
		return 2;
	/********************************************
	   B1段出错
	   1.	正本交易过程标志="01"
       2.	正本钱包累计交易次数-1=副本钱包累计交易次数           
       3.	钱包正本=非法
	*********************************************/
	if ((memcmp(OriginalCommonStr+3, "\x01", 1) == 0) && ((Originaltotalcount -1) == Copytotalcount) && 
		(OriginalMoneyFlag == 1)) 
		return 3;
	/********************************************
	   B2段出错
	   1.	正本交易过程标志="01"
	   2.	正本钱包累计交易次数-1=副本             
       3.	钱包正本=副本
	*********************************************/
	if ((memcmp(OriginalCommonStr+3, "\x01", 1) == 0) && ((Originaltotalcount -1) == Copytotalcount) &&
		(OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) && (OriginalMoneyValue == CopyMoneyValue))
		return 4;
	/********************************************
	   D段出错
	   1.	公共信息区正本=非法
	   2.	公共信息区副本=OK
       3.	钱包正本<钱包副本
	*********************************************/
	if ((OriginalCommonFlag == 1) && (CopyCommonFlag == 0) && (OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) &&
		(OriginalMoneyValue < CopyMoneyValue))
		return 5;
	/********************************************
	   E段出错
	   第一种情况
	   1.	正本交易过程标志="02"
       2.	公共信息区副本=非法
	   3.	钱包正本<钱包副本
	   第二种情况
	   1.	正本交易过程标志="02"
	   2.   公共信息区副本=合法并且正本钱包累计交易次数-1=副本钱包累计交易次数
	   3.	钱包正本<钱包副本
	*********************************************/
	if (((memcmp(OriginalCommonStr+3, "\x02", 1) == 0) && (CopyCommonFlag == 1) && (OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) &&
		(OriginalMoneyValue < CopyMoneyValue)) || ((memcmp(OriginalCommonStr+3, "\x02", 1) == 0) && 
		((Originaltotalcount -1) == Copytotalcount) && (OriginalMoneyFlag ==0) && (CopyMoneyFlag == 0) &&
		(OriginalMoneyValue < CopyMoneyValue)))
		return 6;
	/********************************************
	   F段出错
	   第一种情况
	   1.	正本交易过程标志="02"
       2.	公共信息区正本=副本
	   3.	钱包副本=非法
	   第二种情况
	   1.	正本交易过程标志="02"
	   2.	公共信息区正本=副本
	   3.	钱包副本=合法并且钱包正本<钱包副本
	*********************************************/
	if (((memcmp(OriginalCommonStr+3, "\x02", 1) == 0) && (memcmp(OriginalCommonStrXor, CopyCommonStr, 8) == 0) &&
		(CopyMoneyFlag == 1) && (OriginalMoneyFlag == 0)) || ((memcmp(OriginalCommonStr+3, "\x02", 1) == 0) &&
		(OriginalMoneyFlag == 0) && (CopyMoneyFlag == 0) && (OriginalMoneyValue < CopyMoneyValue)))
		return 7;
	return 0;
}

int STDMETHODCALLTYPE ReadPersonInfo(int Keymode, int Secno, unsigned char *Key, unsigned char *PersonInfo)
/********************************************************************************
说明：读取M1卡片个人基础信息区
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 扇区号
	  Key, 扇区密码
输出: PersonInfo, 个人基础信息
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char read_str[33],PID[21];
	
	memset(read_str, 0x00, sizeof(read_str));
	//验证密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读扇区0块
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr; 
	if ((memcmp(read_str, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9) == 0) || (memcmp(read_str, "\x00\x00\x00\x00\x00\x00\x00\x00\x00", 9) == 0))
	{
		FillString(PersonInfo, 43);
		return 0;
	}
	else
	{
		memcpy(PersonInfo, read_str, 10);//姓名
		FillString(PersonInfo, 10);
		memcpy(PersonInfo+10, read_str+10, 1);//性别
		Hex_Asc(read_str+11, 1, PersonInfo+11);//证件类型
		memcpy(PID, read_str+12, 4);//证件号码
		//读扇区1块
		ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
		if (ret != 0)
			return Dev_ReadErr;
		memcpy(PID+4, read_str, 16);//证件号码
		memcpy(PersonInfo+13, PID, 20);
		FillString(PersonInfo, 33);
		PersonInfo[33]='\0';
		return 0;
	}
}

int STDMETHODCALLTYPE ResumeA(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：M1卡A段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char CopyCommonStrXor[33],write_str[33];
	unsigned char cardcrc[3];

	memset(CopyCommonStrXor, 0x00, sizeof(CopyCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));

	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//公共信息区副本→正本
	memcpy(write_str, CopyCommon, 16);
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeBorC(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：B或C段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char OriginalCommonStrXor[33],write_str[33];
	unsigned char cardcrc[3];

	memset(OriginalCommonStrXor, 0x00, sizeof(OriginalCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	
	/****************************
	  公共信息区操作
	  1.改写公共信息区正本交易过程标志="02"
      2.COPY公共信息区副本
	*****************************/
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//改写公共信息区正本交易过程标志="02"
	OriginalCommon[3] = '\x02';
	memcpy(write_str, OriginalCommon, 15);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	//写公共信息区正本
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	//写公共信息区副本
	ret = Dev_write((HANDLE)icdev, Secno2*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	/****************************
	  公共钱包区操作
	  COPY钱包副本
	*****************************/
	//验证公共钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//钱包正本拷贝到钱包副本
	ret = Dev_restore((HANDLE)icdev, Secno1*4+1);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno1*4+2);
	if (ret != 0)
		return Dev_TransferErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeB1(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：M1卡B1段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char CopyCommonStrXor[33],write_str[33];
	unsigned char cardcrc[3];

	memset(CopyCommonStrXor, 0x00, sizeof(CopyCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));

	/****************************
	  公共钱包区操作
	  钱包副本拷贝到钱包正本
	*****************************/
	//验证公共钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//钱包副本拷贝到钱包正本
	ret = Dev_restore((HANDLE)icdev, Secno1*4+2);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno1*4+1);
	if (ret != 0)
		return Dev_TransferErr;
	/****************************
	  公共信息区操作
	  公共信息区副本拷贝到公共信息区正本
	*****************************/
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//公共信息区副本拷贝到公共信息区正本
	memcpy(write_str, CopyCommon, 16);
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeB2(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：M1卡B2段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char CopyCommonStrXor[33],write_str[33];
	unsigned char cardcrc[3];

	memset(CopyCommonStrXor, 0x00, sizeof(CopyCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));

	/****************************
	  公共信息区操作
	  公共信息区副本拷贝到公共信息区正本
	*****************************/
	//验证公共信息区扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//公共信息区副本拷贝到公共信息区正本
	memcpy(write_str, CopyCommon, 16);
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeD(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：M1卡D段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret,totalcount=0;
	unsigned char OriginalCommonStr[33],OriginalCommonStrXor[33], CopyCommonStrXor[33],write_str[33];
	unsigned char cardcrc[3];
	
	memset(OriginalCommonStr, 0x00, sizeof(OriginalCommonStr));
	memset(OriginalCommonStrXor, 0x00, sizeof(OriginalCommonStrXor));
	memset(CopyCommonStrXor, 0x00, sizeof(CopyCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));

	/****************************
	  公共信息区操作
	  改写公共信息区正本
      1.	副本卡交易指针+1写入正本
      2.	副本钱包累计交易指针+1写入正本
      3.	交易过程标志="02"
      公共信息区正本拷贝到副本
	*****************************/
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	//改写公共信息区正本
	memcpy(OriginalCommonStr, CopyCommon, 16);
	OriginalCommonStr[3] = '\x02';//交易过程标志
	OriginalCommonStr[0] = Hex_LongValue(CopyCommonStrXor, 1)+1;//卡交易指针
	totalcount = Hex_LongValue(CopyCommonStrXor+1, 2)+1;//钱包累计交易指针
	LongValue_Hex(totalcount, 2, OriginalCommonStr+1);
	memcpy(write_str, OriginalCommonStr, 8);
	memcpy(write_str+8, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 7);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	//改写公共信息区副本
	ret = Dev_write((HANDLE)icdev, Secno2*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	/****************************
	  公共钱包区操作
	  COPY钱包副本
	*****************************/
	//验证公共钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//钱包正本拷贝到钱包副本
	ret = Dev_restore((HANDLE)icdev, Secno1*4+1);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno1*4+2);
	if (ret != 0)
		return Dev_TransferErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeE(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：E段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char OriginalCommonStrXor[33], write_str[33];
	unsigned char cardcrc[3];
	
	memset(OriginalCommonStrXor, 0x00, sizeof(OriginalCommonStrXor));
	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));

	/****************************
	  公共信息区操作
      公共信息区正本拷贝到副本
	*****************************/
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	memcpy(write_str, OriginalCommon, 16);
	ret = Dev_write((HANDLE)icdev, Secno2*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	/****************************
	  公共钱包区操作
	  钱包正本拷贝到钱包副本
	*****************************/
	//验证公共钱包密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//钱包正本拷贝到钱包副本
	ret = Dev_restore((HANDLE)icdev, Secno1*4+1);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno1*4+2);
	if (ret != 0)
		return Dev_TransferErr;
	return 0;
}

int STDMETHODCALLTYPE ResumeF(int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
	unsigned char *OriginalMoney, unsigned char *CopyMoney, unsigned char *OriginalCommon, unsigned char *CopyCommon)
/********************************************************************************
说明：F段出错恢复
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
	  Secno1, 钱包扇区号
	  Key1, 钱包扇区密码
	  Secno2, 公共信息扇区号
	  Key2, 公共信息扇区密码
      OriginalMoney, 钱包正本
      CopyMoney, 钱包副本
	  OriginalCommon, 公共信息区正本
      CopyCommon, 公共信息区副本
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	
	/****************************
	  公共钱包区操作
	  钱包正本拷贝到钱包副本
	*****************************/
	//验证公共钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//钱包正本拷贝到钱包副本
	ret = Dev_restore((HANDLE)icdev, Secno1*4+1);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno1*4+2);
	if (ret != 0)
		return Dev_TransferErr;
	return 0;
}

int STDMETHODCALLTYPE GetValue(int Keymode, int Secno, unsigned char *Key, unsigned long *MoneyValue)
/********************************************************************************
说明：M1卡获取钱包金额
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  Key, 钱包扇区密码
输出: MoneyValue, 钱包金额，单位到分
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	
	//验证钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//获取钱包金额
	ret = Dev_readval((HANDLE)icdev, Secno*4+1, MoneyValue);
	if (ret != 0)
		return Dev_ReadValueErr;
	return 0;
}

int STDMETHODCALLTYPE WriteTradeOriginalA(int Keymode, int Secno, unsigned char *Key, 
											  unsigned long *Totalcount,unsigned long *Index)
/********************************************************************************
说明：改写公共信息区正本信息
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 公共信息区扇区号
	  Key, 公共信息区密钥
输出: Totalcount, 钱包累计交易次数
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned long count=0,curindex=0;
	unsigned char read_str[33],write_str[33],temp[33],cardcrc[3];

	memset(read_str, 0x00, sizeof(read_str));
	memset(write_str, 0x00, sizeof(write_str));
	memset(temp, 0x00, sizeof(temp));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读取公共信息扇区0块
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 16);
	memcpy(temp, read_str, 1);
	temp[1] ='\0';//交易指针
	curindex = atol((char *)temp) % 9+1;
	sprintf((char *)write_str, "%x", curindex);
	*Index = curindex;
	memcpy(temp, read_str+1, 2);
	temp[2] = '\0';//钱包累计交易次数
	count = Hex_LongValue(temp, 2) +1;
	*Totalcount = count;
	LongValue_Hex(count, 2, write_str+1);
	write_str[3] = '\x01';
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE WriteTradeOriginalB(int Keymode, int Secno, unsigned char *Key)
/********************************************************************************
说明：M1卡改写公共信息区正本信息交易过程为0x02
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 公共信息扇区号
	  Key, 公共信息区密码
输出: Totalcount, 钱包累计交易次数
      Index, 当前交易指针
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned long count=0,curindex=0;
	unsigned char read_str[33],write_str[33],temp[33],cardcrc[3];

	memset(read_str, 0x00, sizeof(read_str));
	memset(write_str, 0x00, sizeof(write_str));
	memset(temp, 0x00, sizeof(temp));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	
	//验证公共信息扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读取公共信息扇区0块
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 16);
	write_str[3] = '\x02';
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE IncMoneyOriginal (int Keymode, int Secno, unsigned char *Key, 
											unsigned long OldMoney, unsigned long LoadMoney)
/********************************************************************************
说明：M1卡钱包正本加款
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  Key, 钱包扇区密码
	  OldMoney, 加款前金额
      LoadMoney, 钱包加款金额
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned long newmoney=0;
	
	//验证钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//加款
	ret = Dev_increment((HANDLE)icdev, Secno*4+1, LoadMoney);
	if (ret != 0)
		return Dev_IncrementErr;
	//读金额
	ret = Dev_readval((HANDLE)icdev, Secno*4+1, &newmoney);
	if (ret != 0)
		return Dev_ReadValueErr;
	if ((OldMoney + LoadMoney) != newmoney)
		return Dev_IncrementErr;
	return 0;
}

int STDMETHODCALLTYPE WriteRecord(int Keymode, unsigned char *Key, unsigned long Index, unsigned char *Date,
									 unsigned char *Time, unsigned long oldmoney, unsigned long Trademoney, 
									 unsigned char *TradeType)
/********************************************************************************
说明：写钱包交易记录
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      LoadKeyFlag, 0表示不需要下载密码，1表示要下载密码
	  Key3, 3、4、5扇区密码
	  Index, 交易指针
      Date, 交易日期
	  Time, 交易时间
	  oldmoney, 交易前金额
      Trademoney, 交易金额
      TradeType, 交易类型
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret,block=0,index_secno=0;
	unsigned char write_str[33],temp[10],read_str[33];

	memset(write_str, 0x00, sizeof(write_str));
	
	if (((Index-1) / 3) == 0)//写3扇区
	{
		index_secno = 3;
		block = 3*4+(Index-1);
	}
	else if (((Index-1) / 3) == 1)//写4扇区
	{
		index_secno = 4;
		block = 4*4+(Index-4);
	}
	else if (((Index-1) / 3) == 2)//写5扇区
	{
		index_secno = 5;
		block = 5*4+(Index-7);
	}
	Asc_Hex(Date+6, 1, write_str);//交易日期
	Asc_Hex(Time, 3, write_str+1);//交易时间
	LongValue_Hex(oldmoney, 4, temp);//交易前金额
	write_str[4] =temp[3];
	write_str[5] =temp[2];
	write_str[6] =temp[1];
	write_str[7] =temp[0];
	LongValue_Hex(Trademoney, 3, temp);//交易金额
	write_str[8] =temp[2];
	write_str[9] =temp[1];
	write_str[10] =temp[0];
	memcpy(write_str+11, TradeType, 1);//交易类型
	memcpy(write_str+12, "\x00\x00\x00\x00", 4);//机具号
	
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, index_secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//写块信息
	ret = Dev_write((HANDLE)icdev, block, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, block, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memicmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE WriteAddRecord (int Keymode, int Secno1, unsigned char *Key1, int Secno2, unsigned char *Key2, 
										 unsigned long OldMoney, unsigned long LoadMoney, 
										 unsigned char *Adddate, unsigned char *Addtime)
/********************************************************************************
说明：写充值其它记录信息
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      LoadKeyFlag, 0表示不需要下载密码，1表示要下载密码
	  Secno1, 发行区扇区号
	  Key1, 发行区扇区密码
	  Secno2, 钱包区扇区号
	  Key2, 钱包区扇区密码
	  OldMoney, 扣款前金额
      LoadMoney, 钱包充值金额
	  Adddate, 充值日期
	  Addtime, 充值时间
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char write_str[33],cardcrc[3],temp[10],read_str[33];
	unsigned long totalmoney=0;

	memset(write_str, 0x00, sizeof(write_str));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	memset(temp, 0x00, sizeof(temp));
	memset(read_str, 0x00, sizeof(read_str));

	//验证发行区扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno1, Key1);
	if (ret != 0)
		return Dev_AuthErr;
	//写1扇区2块
	Asc_Hex(Adddate,  4, write_str);//充值日期
	Asc_Hex(Addtime, 3, write_str+4);//充值时间
	LongValue_Hex(OldMoney, 4, temp);//充值前金额
	write_str[7] = temp[3];
	write_str[8] = temp[2];
	write_str[9] = temp[1];
	write_str[10] = temp[0];//充值原额
	LongValue_Hex(LoadMoney, 4, temp);//本次充值额
	write_str[11] = temp[3];
	write_str[12] = temp[2];
	write_str[13] = temp[1];
	write_str[14] = temp[0];
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno1*4+2, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno1*4+2, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;

	//验证2扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno2, Key2);
	if (ret != 0)
		return Dev_AuthErr;
	ret = Dev_read((HANDLE)icdev, Secno2*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	totalmoney = Hex_LongValue(read_str, 4) + LoadMoney;//累计充值额
	LongValue_Hex(totalmoney, 4, temp);
	write_str[0] = temp[3];
	write_str[1] = temp[2];
	write_str[2] = temp[1];
	write_str[3] = temp[0];
	totalmoney = OldMoney + LoadMoney;//本次余额
	LongValue_Hex(totalmoney, 4, temp);
	write_str[4] = temp[3];
	write_str[5] = temp[2];
	write_str[6] = temp[1];
	write_str[7] = temp[0];
	memcpy(write_str+8, "\x00\x00\x00\x00", 4);//充值设备号
	memcpy(write_str+12, "\xFF\xFF\xFF", 3);//保留
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno2*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno2*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE CopyTrade(int Keymode, int Secno, unsigned char *Key)
/********************************************************************************
说明：拷贝公共信息区正本到副本
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 公共信息区扇区号
	  Key, 公共信息区扇区密码
输出: 
      
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned long count=0,curindex=0;
	unsigned char read_str[33],write_str[33],temp[33],cardcrc[3];

	memset(read_str, 0x00, sizeof(read_str));
	memset(write_str, 0x00, sizeof(write_str));
	memset(temp, 0x00, sizeof(temp));
	memset(cardcrc, 0x00, sizeof(cardcrc));
	
	//验证公共信息区扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读公共信息区正本
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 16);
	ret = Dev_write((HANDLE)icdev, Secno*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE CopyMoney(int Keymode, int Secno, unsigned char *Key)
/********************************************************************************
说明：拷贝钱包正本到副本
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号 
	  Key, 钱包密钥
输出: 
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	
	//验证钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	ret = Dev_restore((HANDLE)icdev, Secno*4+1);
	if (ret != 0)
		return Dev_RestoreErr;
	ret = Dev_transfer((HANDLE)icdev, Secno*4+2);
	if (ret != 0)
		return Dev_TransferErr;
	return 0;
}

int STDMETHODCALLTYPE DecMoneyOriginal (int Keymode, int Secno, unsigned char *Key, 
											unsigned long OldMoney, unsigned long PurchaseMoney)
/********************************************************************************
说明：钱包正本扣款
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  Key, 钱包扇区密码
	  OldMoney, 扣款前金额
      PurchaseMoney, 钱包扣款金额
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned long newmoney=0;
	
	//验证钱包扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//扣款
	ret = Dev_decrement((HANDLE)icdev, Secno*4+1, PurchaseMoney);
	if (ret != 0)
		return Dev_DecrementErr;
	//读金额
	ret = Dev_readval((HANDLE)icdev, Secno*4+1, &newmoney);
	if (ret != 0)
		return Dev_ReadValueErr;
	if ((OldMoney - PurchaseMoney) != newmoney)
		return Dev_DecrementErr;
	return 0;
}

int STDMETHODCALLTYPE M_1001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData)
/********************************************************************************
说明：修改卡内基础信息
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  InData, 个人基础信息
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char write_str[33],read_str[33];
	
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//写扇区0块
	memcpy(write_str, InData, 10);//姓名
	memcpy(write_str+10, InData+10, 1);//性别
	Asc_Hex(InData+11, 1, write_str+11);//证件类型
	memcpy(write_str+12, InData+13, 4);//证件号码
	ret = ret = Dev_write((HANDLE)icdev, Secno*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	//写扇区1块
	memcpy(write_str, InData+17, 16);//证件号码
	ret = Dev_write((HANDLE)icdev, Secno*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE M_2001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData)
/********************************************************************************
说明：修改启用标志
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  InData, 启用标志
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret;
	unsigned char write_str[33],read_str[33],cardcrc[3];
	
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读扇区0块
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 12);
	Asc_Hex(InData, 1, write_str+12);//启用标志
	memcpy(write_str+13, read_str+13, 2);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = ret = Dev_write((HANDLE)icdev, Secno*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	//写扇区1块
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 8);
	Asc_Hex(InData+2, 4, write_str+8);//启用日期
	memcpy(write_str+12, read_str+12, 3);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE M_3001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData)
/********************************************************************************
说明：修改押金
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 钱包扇区号
	  InData, 启用标志
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret,i;
	unsigned char write_str[33],read_str[33],cardcrc[3];
	
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//写扇区1块
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 12);
	i=atoi((char *)InData);
	LongValue_Hex(i, 2, write_str+12);//押金
	memcpy(write_str+14, read_str+14, 1);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

int STDMETHODCALLTYPE M_4001(int Keymode, int Secno, unsigned char *Key, unsigned char *InData)
/********************************************************************************
说明：写黑名单标志
输入: Keymode, 密钥模式 0-KeyA,4-KeyB
      Secno, 公共信息扇区号
	  InData, 黑名单标志
输出: 无
返回:
	 =0  表示正常
	 <0  表示错误
********************************************************************************/
{
	int ret,i;
	unsigned char write_str[33],read_str[33],cardcrc[3];
	
	//验证扇区密码
	ret = Dev_authentication_pass((HANDLE)icdev, Keymode, Secno, Key);
	if (ret != 0)
		return Dev_AuthErr;
	//读公共信息0块
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	memcpy(write_str, read_str, 5);
	Asc_Hex(InData, 1, write_str+5);
	memcpy(write_str+6, read_str+6, 9);
	Computer_Crc(write_str, cardcrc, 15);//校验位
	Asc_Hex(cardcrc, 1, write_str+15);
	ret = Dev_write((HANDLE)icdev, Secno*4+0, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+0, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	//写公共信息1块
	ret = Dev_write((HANDLE)icdev, Secno*4+1, write_str);
	if (ret != 0)
		return Dev_WriteErr;
	ret = Dev_read((HANDLE)icdev, Secno*4+1, read_str);
	if (ret != 0)
		return Dev_ReadErr;
	if (memcmp(write_str, read_str, 16) !=0)
		return Dev_WriteErr;
	return 0;
}

