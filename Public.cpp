#include "stdafx.h"
#include "stdio.h"
#include <stdlib.h>
#include "fct_des.h"

#include "public.h"

FILE *stream;
extern int logflag;
int STDMETHODCALLTYPE Computer_Crc (unsigned char *Data, unsigned char *Crc, int len)
/*
功能:
	    计算校验位	

参数：
		Data:数据
		Crc:校验位
		len: 长度

返回值:
		成功，返回零。
*/
{
	unsigned char crc_str;
	int i = 0;
	crc_str =0x00;
	for(i = 0; i < len; i++)
		crc_str ^=Data[i];
	sprintf((char *)Crc, "%02x", crc_str);
	return S_OK;
}

long STDMETHODCALLTYPE Hex_LongValue (unsigned char *HEX, int HEXLen)
{ 
	int i;
	unsigned long RetVal;

	RetVal = 0;
	for (i = 0; i < HEXLen; i++)
		RetVal = RetVal * 256 + HEX[i];

	return RetVal;
}


int STDMETHODCALLTYPE LongValue_Hex (long Value, int HEXLen, unsigned char *HEX)
{
	int i;
	unsigned long srcval;
	
	if (Value < 0)	Value = 0;

	srcval = Value;
	for (i = HEXLen - 1; i >= 0; i--)
	{
		HEX[i] = (unsigned char)(srcval % 256);
		srcval /= 256;
	}
	return S_OK;
}

int STDMETHODCALLTYPE Hex_Asc (unsigned char *HEX, int HEXLen, unsigned char *String)
{
	int i;

	for (i = 0; i < HEXLen; i++)
	{
		if (HEX[i] / 16 > 9)
			String[2 * i] = HEX[i] / 16 + 55;
		else
			String[2 * i] = HEX[i] / 16 + 48;
		
		if (HEX[i] % 16 > 9)
			String[2 * i + 1] =  HEX[i] % 16 + 55;
		else
			String[2 * i + 1] =  HEX[i] % 16 + 48;
	}
	String[2 * i] = 0;
	return S_OK;
}


int STDMETHODCALLTYPE Asc_Hex (unsigned char *String, int HEXLen, unsigned char *HEX)
{
	int i;

	for (i = 0; i < HEXLen; i++)
	{
		if (String[2 * i] > 47 && String[2 * i] < 58)		//'0' - '9'
			HEX[i] = (String[2 * i] - 48) * 16;
		else if (String[2 * i] > 64 && String[2 * i] < 71)	//'A' - 'F'
			HEX[i] = (String[2 * i] - 55) * 16;
		else if (String[2 * i] > 96 && String[2 * i] < 103)	//'a' - 'f'
			HEX[i] = (String[2 * i] - 87) * 16;
		else if (String[2 * i] == 0)
		{
			HEX[i] = 0xff;
			break;
		}
		else
			HEX[i] = 0xf0;
		
		if (String[2 * i + 1] > 47 && String[2 * i + 1] < 58)		// '0' - '9'
			HEX[i] += (String[2 * i + 1] - 48);
		else if (String[2 * i + 1] > 64 && String[2 * i + 1] < 71)	//'A' - 'F'
			HEX[i] += (String[2 * i + 1] - 55);
		else if (String[2 * i + 1] > 96 && String[2 * i + 1] < 103)	//'a' - 'f'
			HEX[i] += (String[2 * i + 1] - 87);
		else if (String[2 * i + 1] == 0)
		{
			HEX[i] += 0xf;
			break;
		}
		else
			HEX[i] += 0xf;
	}

	for (i++; i < HEXLen; i++)
		HEX[i] = 0xff;
	HEX[i] = 0;
	return S_OK;
}

int STDMETHODCALLTYPE XorData (unsigned char *Data1, unsigned char *Data2, unsigned char *Middle, int len)
/*
功能:
		异或俩串

参数：
		Data1:源串
		Data2:源串
		Middle:结果
		len: 长度

返回值:
		成功，返回零。
*/
{
	int i = 0;
	for(i = 0; i < len; i++)
		Middle[i] = Data1[i] ^ Data2[i];
	return S_OK;
}

int STDMETHODCALLTYPE FillString (unsigned char *strBuff, int strLen)
//对字符串填充空格到指定长度
{
	int i;

	for (i=strlen((char *)strBuff); i<strLen; i++)
	{
		strBuff[i] = ' ';
	}	
	strBuff[strLen] = 0;

	return strLen;
}

int STDMETHODCALLTYPE Triple3DES (BYTE *Data, BYTE *Key, BYTE *Result)

{
	BYTE Source[9]={0};
	BYTE KeyL[9]={0};
	BYTE KeyR[9]={0};

	memcpy(KeyL,Key,8);
	memcpy(KeyR,&Key[8],8);

	memcpy(Source,Data,8);
	function_des(CIPHER,Source,KeyL,Result);
	memcpy(Source,Result,8);
	function_des(DECIPHER,Source,KeyR,Result);
	memcpy(Source,Result,8);
	function_des(CIPHER,Source,KeyL,Result);
	return 0;
}

void STDMETHODCALLTYPE DumpStr (char *data, unsigned long datalen)
{

	char buff[1000];
	struct tm *newtime;		
	time_t aclock;

	if (logflag==1)//启用写日志标志
	{
		time (&aclock);
		newtime = localtime (&aclock);
		sprintf (buff, "%04d-%02d-%02d %02d:%02d:%02d %s%s", 
				newtime->tm_year+1900, newtime->tm_mon+1, newtime->tm_mday, 
				newtime->tm_hour, newtime->tm_min, newtime->tm_sec, data, "\n");
		if ((stream = fopen( "Card_Operate.txt", "a+b")) != NULL)
		{
			fwrite (buff, datalen+1, 1, stream);
			fclose (stream);
		}
	}
	return;
}
