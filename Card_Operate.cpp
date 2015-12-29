// Card_Operate.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "Card_Operate.h"
#include "public.h"
#include "dev.h"
#include "dev_error.h"
#include "m1.h"
#include "EncryptMachine.h"
#include "app.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//
//	Note!
//
//		If this DLL is dynamically linked against the MFC
//		DLLs, any functions exported from this DLL which
//		call into MFC must have the AFX_MANAGE_STATE macro
//		added at the very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

/////////////////////////////////////////////////////////////////////////////
// CCard_OperateApp

BEGIN_MESSAGE_MAP(CCard_OperateApp, CWinApp)
	//{{AFX_MSG_MAP(CCard_OperateApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CCard_OperateApp construction

CCard_OperateApp::CCard_OperateApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CCard_OperateApp object

CCard_OperateApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CCard_OperateApp initialization

BOOL CCard_OperateApp::InitInstance()
{
	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}
	char data[100];
	memset(data, 0x00, sizeof(data));
	GetPrivateProfileString ("config", "psamid", " ", data, 50, ".\\card_config.ini");
	if (data[0] == '\0')
		GetPrivateProfileString ("config", "psamid", " ", data, 50, "card_config.ini");
	psamid=atoi(data);//PSAM卡座

	GetPrivateProfileString ("Log_Config", "logflag", " ", data, 50, ".\\card_config.ini");
	if (data[0] == '\0')
		GetPrivateProfileString ("Log_Config", "logflag", " ", data, 50, "card_config.ini");
	logflag=atoi(data);
	return TRUE;
}

int STDMETHODCALLTYPE Format_Card(int Port, unsigned char *Hostaddr, unsigned long Hostport,unsigned char *CardInInfo, 
								  unsigned char *CardOutInfo)
/*******************************************
 函数说明：对M1卡片进行初始化操作
 输入值：Port，端口号
		  Cardinfo，输入的发卡信息
  输出值：无
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned long snrno;
	unsigned char key[13],read_data[33],write_data[33],key_in[17],key_out[17],logbuff[200];
	unsigned char cardmac[9],hex_str[20],buff[50],buff_hex[50],Send_data[500],Recv_data[500];
	
	//打开读卡器
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;

	if (memicmp(CardInInfo, "0", 1) == 0)//0从外部传入卡号信息
	{
		memcpy(citycode, CardInInfo+1, 4);//城市代码
		memcpy(buff, CardInInfo+5, 3);//卡类别
		i=atoi((char *)buff);
		LongValue_Hex(i, 1, buff_hex);
		Hex_Asc(buff_hex, 1, cardtype);
		memcpy(cardno, CardInInfo+8, 8);//发行流水号
	}
	if (memicmp(CardInInfo, "1", 1) == 0)//1表示从卡内部读取
	{
		//寻卡
		ret = Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证1扇区密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
		//读1扇区0块
		ret = Dev_read_hex((HANDLE)icdev, 1*4+0, read_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_ReadErr;
		}
		memcpy(citycode, read_data, 4);//城市代码
		memcpy(cardno, read_data+8, 8);//发行流水号
		memcpy(buff, CardInInfo+5, 3);//卡类别
		i=atoi((char *)buff);
		LongValue_Hex(i, 1, buff_hex);
		Hex_Asc(buff_hex, 1, cardtype);

	}
	memcpy(initflag, CardInInfo+16, 2);//启用标志
	memcpy(IssueDate, CardInInfo+18, 8);//发行日期
	memcpy(ValidDate, CardInInfo+26, 8);//有效日期
	memcpy(UseDate, CardInInfo+34, 8);//启用日期
	
	
	
	/**********************************
	 0扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证0扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//读0扇区0块
	ret = Dev_read_hex((HANDLE)icdev, 0*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(cardsn, read_data, 8);//卡序列号
	//写0扇区1块
	memcpy(write_data, "00011003030306FFFFFFFFFFFFFF1615", 32);
	ret = M1_Write(icdev, 0*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/*********************************
	//通过加密机计算卡认证码
	**********************************/
	memcpy(Send_data, "N60010504", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, citycode, 4);//城市代码
	memcpy(Send_data+16, cardsn, 8);//卡序列号
	memcpy(Send_data+24, cardno+4, 4);//发行流水号后4位
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(cardmac, Recv_data, 8);//卡认证码
	//写0扇区2块
	memcpy(write_data, citycode, 4);//城市代码
	memcpy(write_data+4, "0000", 4);//应用代码
	memcpy(write_data+8, cardno, 8);//发行流水号
	memcpy(write_data+16, cardmac, 8);//卡认证码
	memcpy(write_data+24, "000000", 6);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码

	sprintf((char *)logbuff, "%s%s", "0扇区2块数据：", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);

	ret = M1_Write(icdev, 0*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}

	//写0扇区3块控制位
	memcpy(write_data, "A0A1A2A3A4A508778F69", 20);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "00", 2);//0扇区标识
	//加密机计算扇区0 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 1扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证1扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//写1扇区0块
	memcpy(write_data, citycode, 4);//行业代码
	memcpy(write_data+4, "0000", 4);//应用代码
	memcpy(write_data+8, cardno, 8);//发行流水号
	memcpy(write_data+16, cardmac, 8);//卡认证码
	memcpy(write_data+24, initflag, 2);//启用标志
	memcpy(write_data+26, cardtype, 2);//卡类别
	memcpy(write_data+28, "FF", 2);//保留
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码

	sprintf((char *)logbuff, "%s%s", "1扇区0块数据：", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);
	ret = M1_Write(icdev, 1*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写1扇区1块
	memcpy(write_data, IssueDate, 8);//发行日期
	memcpy(write_data+8, ValidDate, 8);//有效日期
	memcpy(write_data+16, UseDate, 8);//启用日期
	memcpy(write_data+24, "0000", 4);//押金
	memcpy(write_data+28, "FF", 2);//保留
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码

	sprintf((char *)logbuff, "%s%s", "1扇区1块数据：", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);
	ret = M1_Write(icdev, 1*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写1扇区2块
	memcpy(write_data, "190001010000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 1*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写1扇区3块（控制位）
	memcpy(write_data, cardsn, 8);
	memcpy(write_data+8, cardsn, 4);
	memcpy(write_data+12, "08778f69", 8);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "01", 2);//1扇区标识
	//加密机计算扇区1 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 1*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	/**********************************
	 2扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证2扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 2, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//写2扇区0块
	memcpy(write_data, "000000000000000000000000FFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 2*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写2扇区1块
	ret=Dev_initval((HANDLE)icdev, 2*4+1, 0);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InitValueErr;
	}
	//写2扇区2块
	ret=Dev_initval((HANDLE)icdev, 2*4+2, 0);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InitValueErr;
	}
	//写2扇区3块（控制块）
	//计算keya
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "10", 2);//2扇区标识
	//加密机计算扇区2 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keya值
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "08778f69", 8);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "02", 2);//2扇区标识
	//加密机计算扇区2 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 2*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	/**********************************
	 3,4,5扇区操作
	 **********************************/
	for (i=3; i<6; i++)
	{
		ret = Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证i扇区密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, i, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
		//写i扇区控制位
		//计算keya
		memcpy(key_in, cardsn, 8);//卡片序列号
		memcpy(key_in+8, cardno+4, 4);//发行流水号
		memcpy(key_in+12, cardmac, 2);//卡认证码
		memcpy(key_in+14, "03", 2);//3、4、5扇区标识
		//加密机计算扇区3、4、5 keya
		memcpy(Send_data, "N60010501", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key_out, Recv_data, 12);//keya值
		memcpy(write_data, key_out, 12);
		memcpy(write_data+12, "7F078869", 8);
		//计算keyb
		memcpy(key_in, cardsn, 8);//卡片序列号
		memcpy(key_in+8, cardno+4, 4);//发行流水号
		memcpy(key_in+12, cardmac, 2);//卡认证码
		memcpy(key_in+14, "03", 2);//3、4、5扇区标识
		//加密机计算扇区3、4、5 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key_out, Recv_data, 12);//keyb值
		memcpy(write_data+20, key_out, 12);
		ret=Dev_write_hex((HANDLE)icdev, i*4+3, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	/**********************************
	 6扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证6扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 6, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//写6扇区0块
	memcpy(write_data, "30000002000000000000FFFFFFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 6*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写6扇区1块
	memcpy(write_data, "30000002000000000000FFFFFFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 6*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写6扇区3块（控制位）
	//计算keya
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "06", 2);//6扇区标识
	//加密机计算扇区6 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keya值
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "7F078869", 8);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "06", 2);//6扇区标识
	//加密机计算扇区6 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 6*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	/**********************************
	 14扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证14扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 14, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//写14扇区0块
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 14*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写14扇区1块
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 14*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写14扇区2块
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//校验码
	ret = M1_Write(icdev, 14*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写14扇区3块（控制位）
	//计算keya
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "16", 2);//7扇区标识
	//加密机计算扇区14 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keya值
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "7F078869", 8);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "14", 2);//7扇区标识
	//加密机计算扇区14 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 14*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 15扇区操作
	 **********************************/
	//寻卡
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证15扇区密码
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 15, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//写15扇区0块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret = M1_Write(icdev, 15*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写15扇区1块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret = M1_Write(icdev, 15*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写15扇区3块（控制位）
	//计算keya
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "15", 2);//15扇区标识
	//加密机计算扇区15 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keya值
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "08778f69", 8);
	//计算keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡认证码
	memcpy(key_in+14, "15", 2);//15扇区标识
	//加密机计算扇区15 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//长度
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyb值
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 15*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	memcpy(CardOutInfo, cardsn, 8);//卡片序列号
	memcpy(CardOutInfo+8, citycode, 4);//城市代码
	memcpy(CardOutInfo+12, cardno, 8);//发行流水号
	CardOutInfo[20] = '\0';
	Dev_beep((HANDLE)icdev, 20);
	//关闭端口
	Dev_exit((HANDLE)icdev);
	return 0;
}

int STDMETHODCALLTYPE Clear_Card(int Port, int Mode,unsigned char *Hostaddr, unsigned long Hostport)
/*******************************************
 函数说明：对M1卡片进行清卡处理
 输入值：Port，端口号
		  Mode，清卡方式，0加密机，1密钥卡
		  Hostaddr，加密机地址
		  Hostport，加密机端口
  输出值：无
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,icdev,i;
	unsigned long snrno;
	unsigned char key[13],read_data[33],write_data[33],hex_str[20];
	unsigned char cardmac[9],key_in[17],Send_data[500],Recv_data[500];
	
	memset(key, 0x00, sizeof(key));
	memset(read_data, 0x00, sizeof(read_data));
	memset(cardsn, 0x00, sizeof(cardsn));
	memset(cardno, 0x00, sizeof(cardno));
	memset(write_data, 0x00, sizeof(write_data));
	memset(cardmac, 0x00, sizeof(cardmac));
	memset(hex_str, 0x00, sizeof(hex_str));

	snrno=0;
	
	//打开读卡器
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;

	/**********************************
	 0扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证0扇区密码
	memcpy(key, "A0A1A2A3A4A5", 12);
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
	if (ret!=0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证0扇区密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//读取0扇区0块
	ret=Dev_read_hex((HANDLE)icdev, 0*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(cardsn, read_data, 8);//卡片序列号
	/**********************************
	 1扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//验证1扇区密码
	memcpy(key, cardsn, 8);
	memcpy(key+8, cardsn, 4);
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证1扇区密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//读1扇区0块
	ret=Dev_read_hex((HANDLE)icdev, 1*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(citycode, read_data, 4);//城市代码
	memcpy(cardno, read_data+8, 8);//发行流水号
	memcpy(cardmac, read_data+16, 8);//卡认证码
	/**********************************
	 0扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算0扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "00", 2);//0扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区0 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证0扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 0, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证0扇区密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//写0扇区1块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	//写0扇区2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	//写0扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 2扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算2扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "02", 2);//2扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证2扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 2, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证2扇区keya密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 2, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
	}
	//写2扇区0，1，2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	for (i=0; i<3; i++)
	{
		ret=Dev_write_hex((HANDLE)icdev, 2*4+i, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	//写2扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 2*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 3,4,5扇区操作
	 **********************************/
	for (i=3; i<6; i++)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//计算3、4、5扇区keyb
		memcpy(key_in, cardsn, 8);//卡片序列号
		memcpy(key_in+8, cardno+4, 4);//发行流水号
		memcpy(key_in+12, cardmac, 2);//卡片认证码
		memcpy(key_in+14, "03", 2);//3、4、5扇区标识
		if (Mode == 0)//加密机
		{
			//加密机计算扇区3、4、5 keyb
			memcpy(Send_data, "N60010101", 9);
			memcpy(Send_data+9, "008", 3);//长度
			memcpy(Send_data+12, key_in, 16);
			ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
			if (ret < 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
			memcpy(key, Recv_data, 12);//keyb值
		}
		//验证扇区密码
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, i, key);
		if (ret != 0)
		{
			//寻卡
			ret=Dev_card((HANDLE)icdev, 1, &snrno);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return Dev_CardSearchErr;
			}
			///验证i扇区keya密码
			memcpy(key, "FFFFFFFFFFFF", 12);
			ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, i, key);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return Dev_AuthErr;
			}
		}
		//写i扇区0，1，2块
		memcpy(write_data, "00000000000000000000000000000000", 32);
		for (int j=0; j<3; j++)
		{
			ret=Dev_write_hex((HANDLE)icdev, i*4+j, write_data);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return Dev_WriteErr;
			}
		}
		//写i扇区3块（控制块）
		memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
		ret=Dev_write_hex((HANDLE)icdev, i*4+3, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	/**********************************
	 6扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算6扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "06", 2);//6扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区6 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 6, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证6扇区keya密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 6, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//写6扇区0，1，2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	for (i=0; i<3; i++)
	{
		ret=Dev_write_hex((HANDLE)icdev, 6*4+i, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	//写6扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 6*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 14扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算14扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "14", 2);//7扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区14 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 14, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证14扇区keya密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 14, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//写14扇区0，1，2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	for (i=0; i<3; i++)
	{
		ret=Dev_write_hex((HANDLE)icdev, 14*4+i, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	//写14扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 14*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	/**********************************
	 15扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算15扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "15", 2);//12扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 15, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证15扇区keya密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 15, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//写15扇区0，1，2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	for (i=0; i<3; i++)
	{
		ret=Dev_write_hex((HANDLE)icdev, 15*4+i, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	//写15扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 15*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	/**********************************
	 1扇区操作
	 **********************************/
	//寻卡
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//计算1扇区keyb
	memcpy(key_in, cardsn, 8);//卡片序列号
	memcpy(key_in+8, cardno+4, 4);//发行流水号
	memcpy(key_in+12, cardmac, 2);//卡片认证码
	memcpy(key_in+14, "01", 2);//1扇区标识
	if (Mode == 0)//加密机
	{
		//加密机计算扇区2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//长度
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keyb值
	}
	//验证扇区密码
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 1, key);
	if (ret != 0)
	{
		//寻卡
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//验证1扇区keya密码
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
	}
	//写1扇区1，2块
	memcpy(write_data, "00000000000000000000000000000000", 32);
	for (i=1; i<3; i++)
	{
		ret=Dev_write_hex((HANDLE)icdev, 1*4+i, write_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_WriteErr;
		}
	}
	//写1扇区3块（控制块）
	memcpy(write_data, "FFFFFFFFFFFFFF078069FFFFFFFFFFFF", 32);
	ret=Dev_write_hex((HANDLE)icdev, 1*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	Dev_beep((HANDLE)icdev, 20);
	//关闭端口
	Dev_exit((HANDLE)icdev);
	return 0;
}

int STDMETHODCALLTYPE Read_Card(int Port, unsigned char *CardInfo)
/*******************************************
 函数说明：读M1卡片信息
 输入值：Port，端口号
  输出值：CardInfo，返回的卡信息
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[8],outstr[500],atr[400];
	unsigned char cardno[9],cardmac[9],cityno[5],key[100],key2[7], key6[7],key15[7],key_in[100],personinfo[44];
	unsigned char OriginalCommonStr[33],CopyCommonStr[33],OriginalMoney[13],CopyMoney[13],blackflag[3];
	unsigned long totalcount=0;
	
	memset(Csn, 0x00, sizeof(Csn));
	memset(key, 0x00, sizeof(key));
	memset(outstr, 0x00, sizeof(outstr));
	memset(cardno, 0x00, sizeof(cardno));
	memset(cardmac, 0x00, sizeof(cardmac));
	memset(cityno, 0x00, sizeof(cityno));
	memset(OriginalCommonStr, 0x00, sizeof(OriginalCommonStr));
	memset(CopyCommonStr, 0x00, sizeof(CopyCommonStr));
	memset(OriginalMoney, 0x00, sizeof(OriginalMoney));
	memset(CopyMoney, 0x00, sizeof(CopyMoney));
	memset(personinfo, 0x00, sizeof(personinfo));

	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//行业代码
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	Hex_Asc(outstr+12, 1, initflag);//启用标志
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+14, 4, IssueDate);//发行日期
	Hex_Asc(outstr+18, 4, ValidDate);//有效日期
	Hex_Asc(outstr+22, 4, UseDate);//启用日期
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//押金
	
	//计算2、6、15扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x02\x06\x15", 3);//2、6、15扇区标识
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Sleep(100);
	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 19, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2扇区keyb
	memcpy(key6, outstr+6, 6);//6扇区keyb
	memcpy(key15, outstr+12, 6);//15扇区keyb
	/****************************
	 * 出错点判断
	*****************************/
	ret = JugeErrorPoint(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//进入恢复流程
	{
		if (ret == 1)//A段出错恢复
		{
			ret = ResumeA(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 2)//B或C段出错恢复
		{
			ret = ResumeBorC(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 3)//B1段出错恢复
		{
			ret = ResumeB1(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 4)//B2段出错恢复
		{
			ret = ResumeB2(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 5)//D段出错恢复
		{
			ret = ResumeD(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 6) //E段出错
		{
			ret = ResumeE(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 7)//F段出错
		{
			ret = ResumeF(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		//恢复后再读取卡信息
		ret = JugeErrorPoint(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//黑名单标志
/*	//判断公共信息区的黑名单标志
	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//钱包累计交易次数
	/****************************
	 * 读取个人基础信息
	*****************************/
	ret = ReadPersonInfo(4, 15, key15, personinfo);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	ret = CloseSession();
	if (ret != 0)
		return ret;
	//组织返回的字符串
	Hex_Asc(Csn, 4, CardInfo);//物理卡号
	memcpy(CardInfo+8, citycode, 4);//城市代码
	memcpy(CardInfo+12, cardno, 8);//发行流水号
	memcpy(CardInfo+20, initflag, 2);//启用标志
	memcpy(CardInfo+22, IssueDate, 8);//发行日期
	memcpy(CardInfo+30, ValidDate, 8);//有效日期
	memcpy(CardInfo+38, UseDate, 8);//启用日期
	memcpy(CardInfo+46, Deposit, 5);//押金
	sprintf((char *)CardInfo+51, "%05u", totalcount);//钱包累计交易次数
	memcpy(CardInfo+56, OriginalMoney, 12);//钱包金额
	memcpy(CardInfo+68, personinfo, 33);//个人基础信息 
	memcpy(CardInfo+101, blackflag, 2);//黑名单标志
	memcpy(CardInfo+103, cardtype, 3);//卡类别
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Read_Card_Psam(int Port, unsigned char *CardInfo)
/*******************************************
 函数说明：通过PSAM卡读M1卡片信息
 输入值：Port，端口号
  输出值：CardInfo，返回的卡信息
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[8],outstr[500],atr[400];
	unsigned char cardno[9],cardmac[9],cityno[5],key[100],key2[7], key6[7],key15[7],key_in[50],personinfo[44];
	unsigned char OriginalCommonStr[33],CopyCommonStr[33],OriginalMoney[13],CopyMoney[13],blackflag[3];
	unsigned long totalcount=0;

	time_t start,end;
	char buff[100];
	
	memset(Csn, 0x00, sizeof(Csn));
	memset(key, 0x00, sizeof(key));
	memset(outstr, 0x00, sizeof(outstr));
	memset(cardno, 0x00, sizeof(cardno));
	memset(cardmac, 0x00, sizeof(cardmac));
	memset(cityno, 0x00, sizeof(cityno));
	memset(OriginalCommonStr, 0x00, sizeof(OriginalCommonStr));
	memset(CopyCommonStr, 0x00, sizeof(CopyCommonStr));
	memset(OriginalMoney, 0x00, sizeof(OriginalMoney));
	memset(CopyMoney, 0x00, sizeof(CopyMoney));
	memset(personinfo, 0x00, sizeof(personinfo));


	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//start = clock();
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//城市代码
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	Hex_Asc(outstr+12, 1, initflag);//启用标志
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+14, 4, IssueDate);//发行日期
	Hex_Asc(outstr+18, 4, ValidDate);//有效日期
	Hex_Asc(outstr+22, 4, UseDate);//启用日期
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//押金
	
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
/*	start = clock();
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	//memcpy(key_in+12, "\x10", 1);
	memcpy(key_in+12, "\x10\x06\x15", 3);//2、6、15扇区标识
	Asc_Hex(citycode, 2, key_in+15);//城市代码
	memcpy(key_in+17, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 23, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	end = clock();
	double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC * 1000;
	memset(buff, 0x30, 50);
	sprintf(buff, "%f",dur);
	MessageBox(NULL,buff,"上电时间(单位为毫秒):",MB_OK);
*/
	//计算2扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x10", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2、6、15扇区标识
	Asc_Hex(citycode, 2, key_in+13);//城市代码
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2扇区keya
	//计算6扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x06", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2、6、15扇区标识
	Asc_Hex(citycode, 2, key_in+13);//城市代码
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6扇区keya
	//计算15扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x15", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2、6、15扇区标识
	Asc_Hex(citycode, 2, key_in+13);//城市代码
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key15, outstr, 6);//15扇区keya

	/****************************
	 * 出错点判断
	*****************************/
	ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//进入恢复流程
	{
		if (ret == 1)//A段出错恢复
		{
			ret = ResumeA(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 2)//B或C段出错恢复
		{
			ret = ResumeBorC(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 3)//B1段出错恢复
		{
			ret = ResumeB1(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 4)//B2段出错恢复
		{
			ret = ResumeB2(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 5)//D段出错恢复
		{
			ret = ResumeD(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 6) //E段出错
		{
			ret = ResumeE(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 7)//F段出错
		{
			ret = ResumeF(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		//恢复后再读取卡信息
		ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//黑名单标志
	//判断公共信息区的黑名单标志
/*	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//钱包累计交易次数
/*	end = clock();
	double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC * 1000;
	memset(buff, 0x30, 50);
	sprintf(buff, "%f",dur);
	MessageBox(NULL,buff,"上电时间(单位为毫秒):",MB_OK);
*/
	/****************************
	 * 读取个人基础信息
	*****************************/
	ret = ReadPersonInfo(0, 15, key15, personinfo);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	
	ret = CloseSession();
	if (ret != 0)
		return ret;
	//组织返回的字符串
	Hex_Asc(Csn, 4, CardInfo);//物理卡号
	memcpy(CardInfo+8, citycode, 4);//城市代码
	memcpy(CardInfo+12, cardno, 8);//发行流水号
	memcpy(CardInfo+20, initflag, 2);//启用标志
	memcpy(CardInfo+22, IssueDate, 8);//发行日期
	memcpy(CardInfo+30, ValidDate, 8);//有效日期
	memcpy(CardInfo+38, UseDate, 8);//启用日期
	memcpy(CardInfo+46, Deposit, 5);//押金
	sprintf((char *)CardInfo+51, "%05u", totalcount);//钱包累计交易次数
	memcpy(CardInfo+56, OriginalMoney, 12);//钱包金额
	memcpy(CardInfo+68, personinfo, 33);//个人基础信息 
	memcpy(CardInfo+101, blackflag, 2);//黑名单标志
	memcpy(CardInfo+103, cardtype, 3);//卡类别
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Read_Card_Second_Psam(int Port, unsigned char *CardInfo)
/*******************************************
 函数说明：通过二级PSAM卡读M1卡片信息
 输入值：Port，端口号
  输出值：CardInfo，返回的卡信息
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[8],outstr[500],atr[400];
	unsigned char cardno[9],cardmac[9],cityno[5],key[100],key2[7], key6[7],key15[7],key_in[50],personinfo[44];
	unsigned char OriginalCommonStr[33],CopyCommonStr[33],OriginalMoney[13],CopyMoney[13],blackflag[3];
	unsigned long totalcount=0;
	
	memset(Csn, 0x00, sizeof(Csn));
	memset(key, 0x00, sizeof(key));
	memset(outstr, 0x00, sizeof(outstr));
	memset(cardno, 0x00, sizeof(cardno));
	memset(cardmac, 0x00, sizeof(cardmac));
	memset(cityno, 0x00, sizeof(cityno));
	memset(OriginalCommonStr, 0x00, sizeof(OriginalCommonStr));
	memset(CopyCommonStr, 0x00, sizeof(CopyCommonStr));
	memset(OriginalMoney, 0x00, sizeof(OriginalMoney));
	memset(CopyMoney, 0x00, sizeof(CopyMoney));
	memset(personinfo, 0x00, sizeof(personinfo));

	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//城市代码
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	Hex_Asc(outstr+12, 1, initflag);//启用标志
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+14, 4, IssueDate);//发行日期
	Hex_Asc(outstr+18, 4, ValidDate);//有效日期
	Hex_Asc(outstr+22, 4, UseDate);//启用日期
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//押金
	
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//计算2扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x10", 1);
	
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2扇区keya
	//计算6扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x06", 1);
	
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6扇区keya
	//计算15扇区Keya
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x15", 1);
	
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key15, outstr, 6);//15扇区keya
	/****************************
	 * 出错点判断
	*****************************/
	ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//进入恢复流程
	{
		if (ret == 1)//A段出错恢复
		{
			ret = ResumeA(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 2)//B或C段出错恢复
		{
			ret = ResumeBorC(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 3)//B1段出错恢复
		{
			ret = ResumeB1(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 4)//B2段出错恢复
		{
			ret = ResumeB2(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 5)//D段出错恢复
		{
			ret = ResumeD(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 6) //E段出错
		{
			ret = ResumeE(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		else if (ret == 7)//F段出错
		{
			ret = ResumeF(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
		}
		//恢复后再读取卡信息
		ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//黑名单标志
	//判断公共信息区的黑名单标志
/*	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//钱包累计交易次数
	/****************************
	 * 读取个人基础信息
	*****************************/
	ret = ReadPersonInfo(0, 15, key15, personinfo);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	ret = CloseSession();
	if (ret != 0)
		return ret;
	//组织返回的字符串
	Hex_Asc(Csn, 4, CardInfo);//物理卡号
	memcpy(CardInfo+8, citycode, 4);//城市代码
	memcpy(CardInfo+12, cardno, 8);//发行流水号
	memcpy(CardInfo+20, initflag, 2);//启用标志
	memcpy(CardInfo+22, IssueDate, 8);//发行日期
	memcpy(CardInfo+30, ValidDate, 8);//有效日期
	memcpy(CardInfo+38, UseDate, 8);//启用日期
	memcpy(CardInfo+46, Deposit, 5);//押金
	sprintf((char *)CardInfo+51, "%05u", totalcount);//钱包累计交易次数
	memcpy(CardInfo+56, OriginalMoney, 12);//钱包金额
	memcpy(CardInfo+68, personinfo, 33);//个人基础信息 
	memcpy(CardInfo+101, blackflag, 2);//黑名单标志
	memcpy(CardInfo+103, cardtype, 3);//卡类别
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Modify_Card(int Port, int Transid, unsigned char *CardInfo)
/*******************************************
 函数说明：写M1卡片信息
 输入值：Port，端口号
		   Transid，交易类型
		  CardInfo，写入的卡信息
  输出值：无
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[5],key[7],outstr[500],key1[7],key15[7],key6[7];
	unsigned char cardmac[9],cardid[16],key_in[50],atr[100];
	
	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//行业代码
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//判断卡号是否一致
	if (memcmp(CardInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Sleep(50);
	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	
	if (Transid==1001)//修改卡内基础信息
	{
		//计算15扇区Keyb
		Asc_Hex(citycode, 2, key_in);//城市代码
		memcpy(key_in+2, Csn, 4);//卡片序列号
		Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
		Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
		memcpy(key_in+12, "\x15", 1);//15扇区标识
		
		//PSAM卡计算扇区密码
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key15, outstr, 6);//15扇区keyb
		ret = M_1001(4, 15, key15, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==2001)//修改启用标志
	{
		//计算1扇区Keyb
		Asc_Hex(citycode, 2, key_in);//城市代码
		memcpy(key_in+2, Csn, 4);//卡片序列号
		Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
		Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
		memcpy(key_in+12, "\x01", 1);//1扇区标识
		
		//PSAM卡计算扇区密码
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key1, outstr, 6);//1扇区keyb
		ret = M_2001(4, 1, key1, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==3001)//修改押金
	{
		//计算1扇区Keyb
		Asc_Hex(citycode, 2, key_in);//城市代码
		memcpy(key_in+2, Csn, 4);//卡片序列号
		Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
		Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
		memcpy(key_in+12, "\x01", 1);//1扇区标识
		
		//PSAM卡计算扇区密码
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key1, outstr, 6);//1扇区keyb
		ret = M_3001(4, 1, key1, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==4001)//修改黑名单标志
	{
		//计算6扇区Keyb
		Asc_Hex(citycode, 2, key_in);//城市代码
		memcpy(key_in+2, Csn, 4);//卡片序列号
		Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
		Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
		memcpy(key_in+12, "\x06", 1);//6扇区标识
		
		//PSAM卡计算扇区密码
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key6, outstr, 6);//6扇区keyb
		ret = M_4001(4, 6, key6, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	ret = CloseSession();
	if (ret != 0)
		return ret;
	return 0;
}

int STDMETHODCALLTYPE Purchase_Card(int Port, unsigned char *PurchaseInInfo, unsigned char *PurchaseOutInfo)
/*******************************************
 函数说明： M1卡片电子钱包消费
 输入值：Port，端口号
		   PurchaseInInfo，消费输入字符串
  输出值：PurchaseOutInfo，消费返回的字符串
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[5],key[7],outstr[500],temp[100],instr[400],key2[7],key3[7],key6[7];
	unsigned char cardmac[9],cardid[17],atr[200];
	unsigned long totalcount=0, oldmoneyvalue=0, purchasemoneyvalue=0,curindex=0;
	unsigned char purchasedate[9],purchasetime[7],tac[9],key_in[50],indata[200];
	
	memset(Csn, 0x00, sizeof(Csn));
	memset(key, 0x00, sizeof(key));
	memset(outstr, 0x00, sizeof(outstr));
	memset(temp, 0x00, sizeof(temp));
	memset(cardmac, 0x00, sizeof(cardmac));
	memset(instr, 0x00, sizeof(instr));
	memset(cardid, 0x00, sizeof(cardid));
	memset(purchasedate, 0x00, sizeof(purchasedate));
	memset(purchasetime, 0x00, sizeof(purchasetime));
	memset(tac, 0x00, sizeof(tac));
	
	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//行业代码
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//判断卡号是否一致
	if (memcmp(PurchaseInInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	ret = Card_FileSel(psamid, 0x00, 0x00, "\x3F\x00", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//读取终端编号
	//选择0016文件
	ret = Card_FileSel(psamid, 0x00, 0x00, "\x00\x16", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Sleep(100);
	ret = Card_ReadBin(psamid, "\x00\x00", 0x00, 0x06, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(atr, 6, isamid);//PSAM卡终端编号

	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//计算2扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x02", 1);//2、3扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2扇区keyb
	//计算3扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x03", 1);//3扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key3, outstr, 6);//3扇区keyb
	//计算6扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x06", 1);//6扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6扇区keyb
	//获取钱包金额
	ret = GetValue(4, 2, key2, &oldmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//判断钱包金额是否满足扣款要求
	memcpy(temp, PurchaseInInfo+12, 12);//扣款金额
	temp[12] = '\0';
	purchasemoneyvalue = atol((char *)temp);
	if (purchasemoneyvalue > oldmoneyvalue)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InsufficiencyErr;
	}
	
	//改写公共信息区正本交易过程标志为01,累计交易次数++
	ret = WriteTradeOriginalA(4, 6, key6, &totalcount, &curindex);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//钱包扣款
	ret = DecMoneyOriginal(4, 2, key2, oldmoneyvalue, purchasemoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写交易记录
	memcpy(purchasedate, PurchaseInInfo+24, 8);//交易日期
	memcpy(purchasetime, PurchaseInInfo+32, 6);//交易时间
	ret = WriteRecord(4, key3, curindex, purchasedate, purchasetime, oldmoneyvalue, purchasemoneyvalue, 
		(unsigned char *)"\x06");
	if (ret != 0)
		goto response;
	//改写公共信息正本交易过程为02
	ret = WriteTradeOriginalB(4, 6, key6);
	if (ret != 0)
		goto response;

	//拷贝公共信息正本到副本
	ret = CopyTrade(4, 6, key6);
	if (ret !=0)
		goto response;
	//拷贝钱包正本到副本
	ret = CopyMoney(4, 2, key2);
	if (ret !=0)
		goto response;
response:
	Hex_Asc(Csn, 4, PurchaseOutInfo);//物理卡号
	memcpy(PurchaseOutInfo+8, cardid, 12);//卡号
	sprintf((char *)PurchaseOutInfo+20, "%05u", totalcount);//钱包累计交易次数
	sprintf((char *)PurchaseOutInfo+25, "%012u", oldmoneyvalue);//钱包原额
	sprintf((char *)PurchaseOutInfo+37, "%012u", purchasemoneyvalue);//交易金额
	memcpy(PurchaseOutInfo+49, purchasedate, 8);//交易日期
	memcpy(PurchaseOutInfo+57, purchasetime, 6);//交易时间
	memcpy(PurchaseOutInfo+63, "06", 2);//交易类型标识,06表示消费
	memcpy(PurchaseOutInfo+65, isamid, 12);//PSAM卡终端编号
	LongValue_Hex(purchasemoneyvalue, 3, indata);//交易金额
	Asc_Hex(purchasedate, 4, indata+3);//交易日期 
	Asc_Hex(purchasetime, 3, indata+7);//交易时间
	LongValue_Hex(totalcount, 2, indata+10);//钱包交易次数
	Asc_Hex(isamid, 6, indata+12);//SAM卡终端机编号
	Asc_Hex(cardno, 4, indata+18);
	memcpy(indata+22, "\xFF\xFF", 2);//预留
	memcpy(indata+24, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
	//计算TAC
	ret = Card_ComputerTAC(psamid, 0, indata, 32, indata, tac);
	if (ret < 0)
		memcpy(tac, "\x00\x00\x00\x00", 4);
	Hex_Asc(tac, 4, PurchaseOutInfo+77);//tac
	PurchaseOutInfo[85] = '\0';
	ret = CloseSession();
	if (ret != 0)
		return ret;
	return 0;
}

int STDMETHODCALLTYPE Load_Card(int Port, unsigned char *LoadInInfo, unsigned char *LoadOutInfo)
/*******************************************
 函数说明： M1卡片电子钱包充值
 输入值：Port，端口号
		   LoadInInfo，充值输入字符串
  输出值：LoadOutInfo，充值返回的字符串
  返回值：=0，表示成功
		  !=0，返回的错误代码
********************************************/
{
	int ret,i;
	unsigned char Csn[5],key[7],key1[7],key2[7],key3[7],key6[7],outstr[500],temp[100],atr[100];
	unsigned long totalcount=0, oldmoneyvalue=0, addmoneyvalue=0,curindex=0, maxmoney=0;
	unsigned char adddate[9],addtime[7],tac[9],cardid[17],cardmac[9],key_in[50],indata[200];
	
	memset(Csn, 0x00, sizeof(Csn));
	memset(outstr, 0x00, sizeof(outstr));
	memset(temp, 0x00, sizeof(temp));
	memset(adddate, 0x00, sizeof(adddate));
	memset(addtime, 0x00, sizeof(addtime));
	memset(tac, 0x00, sizeof(tac));
	icdev = 0;
	ret = OpenSession(Port, Csn);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	/****************************
	 * 读1扇区卡片发行区
	*****************************/
	memcpy(key, Csn, 4);
	memcpy(key+4, Csn, 2);
	ret = ReadVerify(key, outstr);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(outstr, 2, citycode);//行业代码
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//卡类别
	Hex_Asc(outstr+4, 4, cardno);//发行流水号
	Hex_Asc(outstr+8, 4, cardmac);//卡认证码
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//判断卡号是否一致
	if (memcmp(LoadInInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	//PSAM卡复位
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//读取终端编号
	//选择0016文件
	ret = Card_FileSel(psamid, 0x00, 0x00, "\x00\x16", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	ret = Card_ReadBin(psamid, "\x00\x00", 0x00, 0x06, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Hex_Asc(atr, 6, isamid);//PSAM卡终端编号
	//PSAM卡选择DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//计算1扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x01", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1、2、3、6扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key1, outstr, 6);//1扇区keyb
	//计算2扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x02", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1、2、3、6扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2扇区keyb
	//计算3扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x03", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1、2、3、6扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key3, outstr, 6);//3扇区keyb
	//计算6扇区Keyb
	Asc_Hex(citycode, 2, key_in);//城市代码
	memcpy(key_in+2, Csn, 4);//卡片序列号
	Asc_Hex(cardno+4, 2, key_in+6);//发行流水号
	Asc_Hex(cardmac, 4, key_in+8);//卡片认证码
	memcpy(key_in+12, "\x06", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1、2、3、6扇区标识
	//PSAM卡计算扇区密码
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6扇区keyb
	//获取钱包金额
	ret = GetValue(4, 2, key2, &oldmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(temp, LoadInInfo+12, 12);//充值金额
	temp[12] = '\0';
	addmoneyvalue = atol((char *)temp);

	memcpy(temp, LoadInInfo+38, 12);//最大充值金额
	temp[12] = '\0';
	maxmoney = atol((char *)temp);
	if ((oldmoneyvalue + addmoneyvalue) > maxmoney)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_MoneyOverErr;
	}
	//改写公共信息区正本交易过程标志为01,累计交易次数++
	ret = WriteTradeOriginalA(4, 6, key6, &totalcount, &curindex);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//钱包加款
	ret = IncMoneyOriginal(4, 2, key2, oldmoneyvalue, addmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//写交易记录
	memcpy(adddate, LoadInInfo+24, 8);//交易日期
	memcpy(addtime, LoadInInfo+32, 6);//交易时间
	ret = WriteRecord(4, key3, curindex, adddate, addtime, oldmoneyvalue, addmoneyvalue, 
		(unsigned char *)"\x02");
	if (ret != 0)
		goto response;
	//写充值其它信息记录
	ret = WriteAddRecord(4, 1, key1, 2, key2, oldmoneyvalue, addmoneyvalue, adddate, addtime);
	if (ret != 0)
		goto response;

	//改写公共信息正本交易过程为02
	ret = WriteTradeOriginalB(4, 6, key6);
	if (ret != 0)
		goto response;

	//拷贝公共信息正本到副本
	ret = CopyTrade(4, 6, key6);
	if (ret !=0)
		goto response;
	//拷贝钱包正本到副本
	ret = CopyMoney(4, 2, key2);
	if (ret !=0)
		goto response;
	
response:
	
	memcpy(tac, "00000000", 8);//tac
	Hex_Asc(Csn, 4, LoadOutInfo);//物理卡号
	memcpy(LoadOutInfo+8, cardid, 12);//卡号
	sprintf((char *)LoadOutInfo+20, "%05u", totalcount);//钱包累计交易次数
	sprintf((char *)LoadOutInfo+25, "%012u", oldmoneyvalue);//钱包原额
	sprintf((char *)LoadOutInfo+37, "%012u", addmoneyvalue);//交易金额
	memcpy(LoadOutInfo+49, adddate, 8);//交易日期
	memcpy(LoadOutInfo+57, addtime, 6);//交易时间
	memcpy(LoadOutInfo+63, "02", 2);//交易类型标识,02表示充值
	memcpy(LoadOutInfo+65, isamid, 12);//isam卡终端编号
	LongValue_Hex(addmoneyvalue, 3, indata);//交易金额
	Asc_Hex(adddate, 4, indata+3);//交易日期 
	Asc_Hex(addtime, 3, indata+7);//交易时间
	LongValue_Hex(totalcount, 2, indata+10);//钱包交易次数
	Asc_Hex(isamid, 6, indata+12);//SAM卡终端机编号
	Asc_Hex(cardno, 4, indata+18);
	memcpy(indata+22, "\xFF\xFF", 2);//预留
	memcpy(indata+24, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
	//计算TAC
	ret = Card_ComputerTAC(psamid, 0, indata, 32, indata, tac);
	if (ret < 0)
		memcpy(tac, "\x00\x00\x00\x00", 4);
	Hex_Asc(tac, 4, LoadOutInfo+77);//tac
	LoadOutInfo[85] = '\0';
	ret = CloseSession();
	if (ret != 0)
		return ret;
	return 0;
}

int STDMETHODCALLTYPE Read_PIDinfo(int Port,char *name, char *sex, char *nation, char *birth, char *address, char *number, 
								   char *department, char *validdate)
/*******************************************
 函数说明： 读取身份证信息
 输入值：Port 端口号
  输出值：name 姓名
		  sex 性别
		   nation 民族
		   birth 出生日期
		   address 住址
		   number 身份证卡证件号码 
		  department 身份证卡签发机关 
		  validdate 有效日期
  返回值：=0，表示成功
		  <0，返回的错误代码
********************************************/
{
	int ret;

	//打开端口
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;
	ret = Dev_readinfo((HANDLE)icdev, name, sex, nation, birth, address, number, department, validdate);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Dev_beep((HANDLE)icdev, 20);
	Dev_exit((HANDLE)icdev);
	return 0;
}
