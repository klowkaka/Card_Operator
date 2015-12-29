#include "StdAfx.h"
#include "Stdlib.h"
#include "public.h"
#include "app.h"
#include "dev.h"
#include "dev_error.h"
extern int icdev;
#define RWBUFFLEN			(0x82)	//读卡一次最大数据长度（字节）

int STDMETHODCALLTYPE Card_FileSel (int Psamid, int Type, int Mode, char *FileID, int IDLen, char *OutData)
/*********************************************************************
说明：	选择文件，包括数据文件（EF）、目录文件（ADF）。通过文件标识选择。
参数：	Type，输入选择类型，0=MF/1=目录/2=数据文件/4=应用环境。
		Mode，输入操作类型：0＝第一个文件；2＝下一个文件
		FileID，输入2个字符的文件标识二进制串，如：
			0xEF05、0xDF01等；
			对于输入类型4，应输入应用环境名称字符串，如：
			"sx1.sh.社会保障"、"1PAY.SYS.DDF01"。
		IDLen：FileID的长度
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int oLen, iLen;
	unsigned char R_APDU[100];
	unsigned char C_APDU[100];

	C_APDU[0] = 0x00;
	C_APDU[1] = 0xA4;
	C_APDU[2] = Type;
	C_APDU[3] = Mode;
	C_APDU[4] = IDLen;						//Lc
	memcpy (C_APDU+5, FileID, IDLen);		//data：file tag
	iLen = 5 + IDLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_ReadBin (int Psamid, char *FileID, int Offset, int DataLen, unsigned char *Data)
/*********************************************************************
说明：	读取二进制数据文件内容。
参数：	FileID，输入文件标识二进制串。
		Offset，输入读取数据起始地址。
		DataLen，输入读取数据长度。
		Data，输出读取数据二进制串，注意分配足够空间。
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int response, i, j, h, l;
	int iLen, oLen;
	unsigned char R_APDU[RWBUFFLEN+20];
	unsigned char C_APDU[100];

	if ((Offset < 0xff) && (DataLen < RWBUFFLEN))	//短数据，一次性操作
	{
		C_APDU[0] = 0x00;						//CLA
		C_APDU[1] = 0xb0;						//INS
		C_APDU[2] = 0x00;	//P1(0x80 + SFI)FileID换算成SFI
		C_APDU[3] = Offset & 0xff;				//P2(offset)
		C_APDU[4] = DataLen & 0xff;				//Le(data len)
		iLen = 5;
		oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
		if (oLen < 0)
			return oLen;
		memcpy (Data, R_APDU, oLen-2);		//返回数据
		return oLen-2;
	}
	else		//长数据，分次操作，先选文件
	{
		//选择文件
		response = Card_FileSel (Psamid, 0, 0, FileID, 2, (char *)R_APDU);
		if (0 > response)
			return response;
		
		j = DataLen / RWBUFFLEN;
		for (i=0; i<=j; i++)
		{
			C_APDU[0] = 0x00;					//CLA
			C_APDU[1] = 0xb0;					//INS
			h = (RWBUFFLEN * i) / 256;
			l = (RWBUFFLEN * i) % 256;
			C_APDU[2] = h & 0xff;	            //P1(高位地址)
			C_APDU[3] = l & 0xff;			    //P2(地位地址)

			if (i == j)		//最后一块数据
			{
				C_APDU[4] = (DataLen - RWBUFFLEN * i) & 0xff;	//Le (data len)
				iLen = 5;
				oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
				if (oLen < 0)
					return oLen;
				memcpy (Data + RWBUFFLEN * i, R_APDU, oLen-2);
				break;
			}
			else
			{
				C_APDU[4] = RWBUFFLEN & 0xff;	//Le (data len)
				iLen = 5;
				oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
				if (oLen < 0)
					return oLen;
				memcpy (Data + RWBUFFLEN * i, R_APDU, RWBUFFLEN);	
			}
		}
	}
	return DataLen+2;
}

int STDMETHODCALLTYPE Card_CalKey (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData)
/*********************************************************************
说明：	计算扇区密码
参数：	Type，输入选择类型，0=MF/1=目录/2=数据文件/4=应用环境。
		Mode，输入操作类型：0＝第一个文件；2＝下一个文件
		FileID，输入2个字符的文件标识二进制串，如：
			0xEF05、0xDF01等；
			对于输入类型4，应输入应用环境名称字符串，如：
			"sx1.sh.社会保障"、"1PAY.SYS.DDF01"。
		IDLen：FileID的长度
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int oLen, iLen;
	unsigned char R_APDU[500];
	unsigned char C_APDU[500];

	C_APDU[0] = 0x80;
	C_APDU[1] = 0xFC;
	C_APDU[2] = P1;
	C_APDU[3] = P2;
	C_APDU[4] = InLen;						//Lc
	memcpy (C_APDU+5, InData, InLen);		//data：file tag
	iLen = 5 + InLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_InitDes (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData)
/*********************************************************************
说明：	加密初始化
参数：	Type，输入选择类型，0=MF/1=目录/2=数据文件/4=应用环境。
		Mode，输入操作类型：0＝第一个文件；2＝下一个文件
		FileID，输入2个字符的文件标识二进制串，如：
			0xEF05、0xDF01等；
			对于输入类型4，应输入应用环境名称字符串，如：
			"sx1.sh.社会保障"、"1PAY.SYS.DDF01"。
		IDLen：FileID的长度
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int oLen, iLen;
	unsigned char R_APDU[100];
	unsigned char C_APDU[100];

	C_APDU[0] = 0x80;
	C_APDU[1] = 0x1A;
	C_APDU[2] = P1;
	C_APDU[3] = P2;
	C_APDU[4] = InLen;						//Lc
	memcpy (C_APDU+5, InData, InLen);		//data：file tag
	iLen = 5 + InLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_Des (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData)
/*********************************************************************
说明：	加密
参数：	Type，输入选择类型，0=MF/1=目录/2=数据文件/4=应用环境。
		Mode，输入操作类型：0＝第一个文件；2＝下一个文件
		FileID，输入2个字符的文件标识二进制串，如：
			0xEF05、0xDF01等；
			对于输入类型4，应输入应用环境名称字符串，如：
			"sx1.sh.社会保障"、"1PAY.SYS.DDF01"。
		IDLen：FileID的长度
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int oLen, iLen;
	unsigned char R_APDU[100];
	unsigned char C_APDU[100];

	C_APDU[0] = 0x80;
	C_APDU[1] = 0xFA;
	C_APDU[2] = P1;
	C_APDU[3] = P2;
	C_APDU[4] = InLen;						//Lc
	memcpy (C_APDU+5, InData, InLen);		//data：file tag
	iLen = 5 + InLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_ComputerTAC (int Psamid, int Len1, unsigned char *Indata1, int Len2, unsigned char *Indata2,
										unsigned char *TAC)
/*********************************************************************
说明：	计算TAC
参数：	
返回：	0，成功
　　　	<0，错误码
*********************************************************************/
{
	int ret;
	unsigned char outdata[200];
	ret = Card_InitDes(Psamid, 0x06, 0x00, Len1, Indata1, outdata);
	if (ret < 0)
		return ret;
	ret = Card_Des(Psamid, 0x05, 0x00, Len2, Indata2, TAC);
	if (ret < 0)
		return ret;
	return 0;
}






