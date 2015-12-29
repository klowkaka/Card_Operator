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
	psamid=atoi(data);//PSAM����

	GetPrivateProfileString ("Log_Config", "logflag", " ", data, 50, ".\\card_config.ini");
	if (data[0] == '\0')
		GetPrivateProfileString ("Log_Config", "logflag", " ", data, 50, "card_config.ini");
	logflag=atoi(data);
	return TRUE;
}

int STDMETHODCALLTYPE Format_Card(int Port, unsigned char *Hostaddr, unsigned long Hostport,unsigned char *CardInInfo, 
								  unsigned char *CardOutInfo)
/*******************************************
 ����˵������M1��Ƭ���г�ʼ������
 ����ֵ��Port���˿ں�
		  Cardinfo������ķ�����Ϣ
  ���ֵ����
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
********************************************/
{
	int ret,i;
	unsigned long snrno;
	unsigned char key[13],read_data[33],write_data[33],key_in[17],key_out[17],logbuff[200];
	unsigned char cardmac[9],hex_str[20],buff[50],buff_hex[50],Send_data[500],Recv_data[500];
	
	//�򿪶�����
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;

	if (memicmp(CardInInfo, "0", 1) == 0)//0���ⲿ���뿨����Ϣ
	{
		memcpy(citycode, CardInInfo+1, 4);//���д���
		memcpy(buff, CardInInfo+5, 3);//�����
		i=atoi((char *)buff);
		LongValue_Hex(i, 1, buff_hex);
		Hex_Asc(buff_hex, 1, cardtype);
		memcpy(cardno, CardInInfo+8, 8);//������ˮ��
	}
	if (memicmp(CardInInfo, "1", 1) == 0)//1��ʾ�ӿ��ڲ���ȡ
	{
		//Ѱ��
		ret = Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤1��������
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
		//��1����0��
		ret = Dev_read_hex((HANDLE)icdev, 1*4+0, read_data);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_ReadErr;
		}
		memcpy(citycode, read_data, 4);//���д���
		memcpy(cardno, read_data+8, 8);//������ˮ��
		memcpy(buff, CardInInfo+5, 3);//�����
		i=atoi((char *)buff);
		LongValue_Hex(i, 1, buff_hex);
		Hex_Asc(buff_hex, 1, cardtype);

	}
	memcpy(initflag, CardInInfo+16, 2);//���ñ�־
	memcpy(IssueDate, CardInInfo+18, 8);//��������
	memcpy(ValidDate, CardInInfo+26, 8);//��Ч����
	memcpy(UseDate, CardInInfo+34, 8);//��������
	
	
	
	/**********************************
	 0��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤0��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//��0����0��
	ret = Dev_read_hex((HANDLE)icdev, 0*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(cardsn, read_data, 8);//�����к�
	//д0����1��
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
	//ͨ�����ܻ����㿨��֤��
	**********************************/
	memcpy(Send_data, "N60010504", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, citycode, 4);//���д���
	memcpy(Send_data+16, cardsn, 8);//�����к�
	memcpy(Send_data+24, cardno+4, 4);//������ˮ�ź�4λ
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(cardmac, Recv_data, 8);//����֤��
	//д0����2��
	memcpy(write_data, citycode, 4);//���д���
	memcpy(write_data+4, "0000", 4);//Ӧ�ô���
	memcpy(write_data+8, cardno, 8);//������ˮ��
	memcpy(write_data+16, cardmac, 8);//����֤��
	memcpy(write_data+24, "000000", 6);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����

	sprintf((char *)logbuff, "%s%s", "0����2�����ݣ�", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);

	ret = M1_Write(icdev, 0*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}

	//д0����3�����λ
	memcpy(write_data, "A0A1A2A3A4A508778F69", 20);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "00", 2);//0������ʶ
	//���ܻ���������0 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
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
	 1��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤1��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//д1����0��
	memcpy(write_data, citycode, 4);//��ҵ����
	memcpy(write_data+4, "0000", 4);//Ӧ�ô���
	memcpy(write_data+8, cardno, 8);//������ˮ��
	memcpy(write_data+16, cardmac, 8);//����֤��
	memcpy(write_data+24, initflag, 2);//���ñ�־
	memcpy(write_data+26, cardtype, 2);//�����
	memcpy(write_data+28, "FF", 2);//����
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����

	sprintf((char *)logbuff, "%s%s", "1����0�����ݣ�", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);
	ret = M1_Write(icdev, 1*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д1����1��
	memcpy(write_data, IssueDate, 8);//��������
	memcpy(write_data+8, ValidDate, 8);//��Ч����
	memcpy(write_data+16, UseDate, 8);//��������
	memcpy(write_data+24, "0000", 4);//Ѻ��
	memcpy(write_data+28, "FF", 2);//����
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����

	sprintf((char *)logbuff, "%s%s", "1����1�����ݣ�", write_data);
	DumpStr((char *)logbuff, strlen((char *)logbuff)+20);
	ret = M1_Write(icdev, 1*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д1����2��
	memcpy(write_data, "190001010000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 1*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д1����3�飨����λ��
	memcpy(write_data, cardsn, 8);
	memcpy(write_data+8, cardsn, 4);
	memcpy(write_data+12, "08778f69", 8);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "01", 2);//1������ʶ
	//���ܻ���������1 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
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
	 2��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤2��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 2, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//д2����0��
	memcpy(write_data, "000000000000000000000000FFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 2*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д2����1��
	ret=Dev_initval((HANDLE)icdev, 2*4+1, 0);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InitValueErr;
	}
	//д2����2��
	ret=Dev_initval((HANDLE)icdev, 2*4+2, 0);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InitValueErr;
	}
	//д2����3�飨���ƿ飩
	//����keya
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "10", 2);//2������ʶ
	//���ܻ���������2 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyaֵ
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "08778f69", 8);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "02", 2);//2������ʶ
	//���ܻ���������2 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
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
	 3,4,5��������
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
		//��֤i��������
		memcpy(key, "FFFFFFFFFFFF", 12);
		ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, i, key);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_AuthErr;
		}
		//дi��������λ
		//����keya
		memcpy(key_in, cardsn, 8);//��Ƭ���к�
		memcpy(key_in+8, cardno+4, 4);//������ˮ��
		memcpy(key_in+12, cardmac, 2);//����֤��
		memcpy(key_in+14, "03", 2);//3��4��5������ʶ
		//���ܻ���������3��4��5 keya
		memcpy(Send_data, "N60010501", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key_out, Recv_data, 12);//keyaֵ
		memcpy(write_data, key_out, 12);
		memcpy(write_data+12, "7F078869", 8);
		//����keyb
		memcpy(key_in, cardsn, 8);//��Ƭ���к�
		memcpy(key_in+8, cardno+4, 4);//������ˮ��
		memcpy(key_in+12, cardmac, 2);//����֤��
		memcpy(key_in+14, "03", 2);//3��4��5������ʶ
		//���ܻ���������3��4��5 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key_out, Recv_data, 12);//keybֵ
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
	 6��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤6��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 6, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//д6����0��
	memcpy(write_data, "30000002000000000000FFFFFFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 6*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д6����1��
	memcpy(write_data, "30000002000000000000FFFFFFFFFF", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 6*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д6����3�飨����λ��
	//����keya
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "06", 2);//6������ʶ
	//���ܻ���������6 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyaֵ
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "7F078869", 8);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "06", 2);//6������ʶ
	//���ܻ���������6 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
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
	 14��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤14��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 14, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//д14����0��
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 14*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д14����1��
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 14*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д14����2��
	memcpy(write_data, "000000000000000000000000000000", 30);
	Asc_Hex(write_data, 15, hex_str);
	Computer_Crc(hex_str, cardcrc, 15);
	memcpy(write_data+30, cardcrc, 2);//У����
	ret = M1_Write(icdev, 14*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д14����3�飨����λ��
	//����keya
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "16", 2);//7������ʶ
	//���ܻ���������14 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyaֵ
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "7F078869", 8);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "14", 2);//7������ʶ
	//���ܻ���������14 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
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
	 15��������
	 **********************************/
	//Ѱ��
	ret = Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤15��������
	memcpy(key, "FFFFFFFFFFFF", 12);
	ret = Dev_authentication_pass_hex((HANDLE)icdev, 0, 15, key);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_AuthErr;
	}
	//д15����0��
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret = M1_Write(icdev, 15*4+0, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д15����1��
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret = M1_Write(icdev, 15*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д15����3�飨����λ��
	//����keya
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "15", 2);//15������ʶ
	//���ܻ���������15 keya
	memcpy(Send_data, "N60010501", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keyaֵ
	memcpy(write_data, key_out, 12);
	memcpy(write_data+12, "08778f69", 8);
	//����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//����֤��
	memcpy(key_in+14, "15", 2);//15������ʶ
	//���ܻ���������15 keyb
	memcpy(Send_data, "N60010101", 9);
	memcpy(Send_data+9, "008", 3);//����
	memcpy(Send_data+12, key_in, 16);
	ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key_out, Recv_data, 12);//keybֵ
	memcpy(write_data+20, key_out, 12);
	ret=Dev_write_hex((HANDLE)icdev, 15*4+3, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}

	memcpy(CardOutInfo, cardsn, 8);//��Ƭ���к�
	memcpy(CardOutInfo+8, citycode, 4);//���д���
	memcpy(CardOutInfo+12, cardno, 8);//������ˮ��
	CardOutInfo[20] = '\0';
	Dev_beep((HANDLE)icdev, 20);
	//�رն˿�
	Dev_exit((HANDLE)icdev);
	return 0;
}

int STDMETHODCALLTYPE Clear_Card(int Port, int Mode,unsigned char *Hostaddr, unsigned long Hostport)
/*******************************************
 ����˵������M1��Ƭ�����忨����
 ����ֵ��Port���˿ں�
		  Mode���忨��ʽ��0���ܻ���1��Կ��
		  Hostaddr�����ܻ���ַ
		  Hostport�����ܻ��˿�
  ���ֵ����
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	
	//�򿪶�����
	icdev = (int)Dev_Init(Port-1, 115200);
	if (icdev < 0)
		return Dev_OpenCommErr;

	/**********************************
	 0��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤0��������
	memcpy(key, "A0A1A2A3A4A5", 12);
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 0, key);
	if (ret!=0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤0��������
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
	//��ȡ0����0��
	ret=Dev_read_hex((HANDLE)icdev, 0*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(cardsn, read_data, 8);//��Ƭ���к�
	/**********************************
	 1��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//��֤1��������
	memcpy(key, cardsn, 8);
	memcpy(key+8, cardsn, 4);
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 0, 1, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤1��������
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
	//��1����0��
	ret=Dev_read_hex((HANDLE)icdev, 1*4+0, read_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_ReadErr;
	}
	memcpy(citycode, read_data, 4);//���д���
	memcpy(cardno, read_data+8, 8);//������ˮ��
	memcpy(cardmac, read_data+16, 8);//����֤��
	/**********************************
	 0��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����0����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "00", 2);//0������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������0 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤0��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 0, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤0��������
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
	//д0����1��
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+1, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	//д0����2��
	memcpy(write_data, "00000000000000000000000000000000", 32);
	ret=Dev_write_hex((HANDLE)icdev, 0*4+2, write_data);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_WriteErr;
	}
	//д0����3�飨���ƿ飩
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
	 2��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����2����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "02", 2);//2������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤2��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 2, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤2����keya����
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
	//д2����0��1��2��
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
	//д2����3�飨���ƿ飩
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
	 3,4,5��������
	 **********************************/
	for (i=3; i<6; i++)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//����3��4��5����keyb
		memcpy(key_in, cardsn, 8);//��Ƭ���к�
		memcpy(key_in+8, cardno+4, 4);//������ˮ��
		memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
		memcpy(key_in+14, "03", 2);//3��4��5������ʶ
		if (Mode == 0)//���ܻ�
		{
			//���ܻ���������3��4��5 keyb
			memcpy(Send_data, "N60010101", 9);
			memcpy(Send_data+9, "008", 3);//����
			memcpy(Send_data+12, key_in, 16);
			ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
			if (ret < 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return ret;
			}
			memcpy(key, Recv_data, 12);//keybֵ
		}
		//��֤��������
		ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, i, key);
		if (ret != 0)
		{
			//Ѱ��
			ret=Dev_card((HANDLE)icdev, 1, &snrno);
			if (ret != 0)
			{
				Dev_beep((HANDLE)icdev, 10);
				Dev_beep((HANDLE)icdev, 10);
				Dev_exit((HANDLE)icdev);
				return Dev_CardSearchErr;
			}
			///��֤i����keya����
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
		//дi����0��1��2��
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
		//дi����3�飨���ƿ飩
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
	 6��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����6����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "06", 2);//6������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������6 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 6, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤6����keya����
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
	//д6����0��1��2��
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
	//д6����3�飨���ƿ飩
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
	 14��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����14����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "14", 2);//7������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������14 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 14, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤14����keya����
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
	//д14����0��1��2��
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
	//д14����3�飨���ƿ飩
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
	 15��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����15����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "15", 2);//12������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 15, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤15����keya����
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
	//д15����0��1��2��
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
	//д15����3�飨���ƿ飩
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
	 1��������
	 **********************************/
	//Ѱ��
	ret=Dev_card((HANDLE)icdev, 1, &snrno);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardSearchErr;
	}
	//����1����keyb
	memcpy(key_in, cardsn, 8);//��Ƭ���к�
	memcpy(key_in+8, cardno+4, 4);//������ˮ��
	memcpy(key_in+12, cardmac, 2);//��Ƭ��֤��
	memcpy(key_in+14, "01", 2);//1������ʶ
	if (Mode == 0)//���ܻ�
	{
		//���ܻ���������2 keyb
		memcpy(Send_data, "N60010101", 9);
		memcpy(Send_data+9, "008", 3);//����
		memcpy(Send_data+12, key_in, 16);
		ret = Send_Machine(Hostaddr, Hostport, 3000, 28, Send_data, 22, Recv_data);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key, Recv_data, 12);//keybֵ
	}
	//��֤��������
	ret=Dev_authentication_pass_hex((HANDLE)icdev, 4, 1, key);
	if (ret != 0)
	{
		//Ѱ��
		ret=Dev_card((HANDLE)icdev, 1, &snrno);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return Dev_CardSearchErr;
		}
		//��֤1����keya����
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
	//д1����1��2��
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
	//д1����3�飨���ƿ飩
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
	//�رն˿�
	Dev_exit((HANDLE)icdev);
	return 0;
}

int STDMETHODCALLTYPE Read_Card(int Port, unsigned char *CardInfo)
/*******************************************
 ����˵������M1��Ƭ��Ϣ
 ����ֵ��Port���˿ں�
  ���ֵ��CardInfo�����صĿ���Ϣ
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//��ҵ����
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	Hex_Asc(outstr+12, 1, initflag);//���ñ�־
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+14, 4, IssueDate);//��������
	Hex_Asc(outstr+18, 4, ValidDate);//��Ч����
	Hex_Asc(outstr+22, 4, UseDate);//��������
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//Ѻ��
	
	//����2��6��15����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x02\x06\x15", 3);//2��6��15������ʶ
	//PSAM����λ
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Sleep(100);
	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 19, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2����keyb
	memcpy(key6, outstr+6, 6);//6����keyb
	memcpy(key15, outstr+12, 6);//15����keyb
	/****************************
	 * ������ж�
	*****************************/
	ret = JugeErrorPoint(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//����ָ�����
	{
		if (ret == 1)//A�γ���ָ�
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
		else if (ret == 2)//B��C�γ���ָ�
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
		else if (ret == 3)//B1�γ���ָ�
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
		else if (ret == 4)//B2�γ���ָ�
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
		else if (ret == 5)//D�γ���ָ�
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
		else if (ret == 6) //E�γ���
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
		else if (ret == 7)//F�γ���
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
		//�ָ����ٶ�ȡ����Ϣ
		ret = JugeErrorPoint(4, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//��������־
/*	//�жϹ�����Ϣ���ĺ�������־
	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//Ǯ���ۼƽ��״���
	/****************************
	 * ��ȡ���˻�����Ϣ
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
	//��֯���ص��ַ���
	Hex_Asc(Csn, 4, CardInfo);//������
	memcpy(CardInfo+8, citycode, 4);//���д���
	memcpy(CardInfo+12, cardno, 8);//������ˮ��
	memcpy(CardInfo+20, initflag, 2);//���ñ�־
	memcpy(CardInfo+22, IssueDate, 8);//��������
	memcpy(CardInfo+30, ValidDate, 8);//��Ч����
	memcpy(CardInfo+38, UseDate, 8);//��������
	memcpy(CardInfo+46, Deposit, 5);//Ѻ��
	sprintf((char *)CardInfo+51, "%05u", totalcount);//Ǯ���ۼƽ��״���
	memcpy(CardInfo+56, OriginalMoney, 12);//Ǯ�����
	memcpy(CardInfo+68, personinfo, 33);//���˻�����Ϣ 
	memcpy(CardInfo+101, blackflag, 2);//��������־
	memcpy(CardInfo+103, cardtype, 3);//�����
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Read_Card_Psam(int Port, unsigned char *CardInfo)
/*******************************************
 ����˵����ͨ��PSAM����M1��Ƭ��Ϣ
 ����ֵ��Port���˿ں�
  ���ֵ��CardInfo�����صĿ���Ϣ
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//���д���
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	Hex_Asc(outstr+12, 1, initflag);//���ñ�־
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+14, 4, IssueDate);//��������
	Hex_Asc(outstr+18, 4, ValidDate);//��Ч����
	Hex_Asc(outstr+22, 4, UseDate);//��������
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//Ѻ��
	
	//PSAM����λ
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
/*	start = clock();
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	//memcpy(key_in+12, "\x10", 1);
	memcpy(key_in+12, "\x10\x06\x15", 3);//2��6��15������ʶ
	Asc_Hex(citycode, 2, key_in+15);//���д���
	memcpy(key_in+17, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM��������������
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
	MessageBox(NULL,buff,"�ϵ�ʱ��(��λΪ����):",MB_OK);
*/
	//����2����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x10", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2��6��15������ʶ
	Asc_Hex(citycode, 2, key_in+13);//���д���
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2����keya
	//����6����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x06", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2��6��15������ʶ
	Asc_Hex(citycode, 2, key_in+13);//���д���
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6����keya
	//����15����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x15", 1);
	//memcpy(key_in+12, "\x10\x06\x15", 3);//2��6��15������ʶ
	Asc_Hex(citycode, 2, key_in+13);//���д���
	memcpy(key_in+15, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 21, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key15, outstr, 6);//15����keya

	/****************************
	 * ������ж�
	*****************************/
	ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//����ָ�����
	{
		if (ret == 1)//A�γ���ָ�
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
		else if (ret == 2)//B��C�γ���ָ�
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
		else if (ret == 3)//B1�γ���ָ�
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
		else if (ret == 4)//B2�γ���ָ�
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
		else if (ret == 5)//D�γ���ָ�
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
		else if (ret == 6) //E�γ���
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
		else if (ret == 7)//F�γ���
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
		//�ָ����ٶ�ȡ����Ϣ
		ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//��������־
	//�жϹ�����Ϣ���ĺ�������־
/*	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//Ǯ���ۼƽ��״���
/*	end = clock();
	double dur = static_cast<double>(end - start) / CLOCKS_PER_SEC * 1000;
	memset(buff, 0x30, 50);
	sprintf(buff, "%f",dur);
	MessageBox(NULL,buff,"�ϵ�ʱ��(��λΪ����):",MB_OK);
*/
	/****************************
	 * ��ȡ���˻�����Ϣ
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
	//��֯���ص��ַ���
	Hex_Asc(Csn, 4, CardInfo);//������
	memcpy(CardInfo+8, citycode, 4);//���д���
	memcpy(CardInfo+12, cardno, 8);//������ˮ��
	memcpy(CardInfo+20, initflag, 2);//���ñ�־
	memcpy(CardInfo+22, IssueDate, 8);//��������
	memcpy(CardInfo+30, ValidDate, 8);//��Ч����
	memcpy(CardInfo+38, UseDate, 8);//��������
	memcpy(CardInfo+46, Deposit, 5);//Ѻ��
	sprintf((char *)CardInfo+51, "%05u", totalcount);//Ǯ���ۼƽ��״���
	memcpy(CardInfo+56, OriginalMoney, 12);//Ǯ�����
	memcpy(CardInfo+68, personinfo, 33);//���˻�����Ϣ 
	memcpy(CardInfo+101, blackflag, 2);//��������־
	memcpy(CardInfo+103, cardtype, 3);//�����
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Read_Card_Second_Psam(int Port, unsigned char *CardInfo)
/*******************************************
 ����˵����ͨ������PSAM����M1��Ƭ��Ϣ
 ����ֵ��Port���˿ں�
  ���ֵ��CardInfo�����صĿ���Ϣ
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//���д���
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	Hex_Asc(outstr+12, 1, initflag);//���ñ�־
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+14, 4, IssueDate);//��������
	Hex_Asc(outstr+18, 4, ValidDate);//��Ч����
	Hex_Asc(outstr+22, 4, UseDate);//��������
	i=Hex_LongValue(outstr+26, 2);
	sprintf((char *)Deposit, "%05d", i);//Ѻ��
	
	//PSAM����λ
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//����2����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x10", 1);
	
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2����keya
	//����6����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x06", 1);
	
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6����keya
	//����15����Keya
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x15", 1);
	
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key15, outstr, 6);//15����keya
	/****************************
	 * ������ж�
	*****************************/
	ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	if (ret > 0)//����ָ�����
	{
		if (ret == 1)//A�γ���ָ�
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
		else if (ret == 2)//B��C�γ���ָ�
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
		else if (ret == 3)//B1�γ���ָ�
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
		else if (ret == 4)//B2�γ���ָ�
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
		else if (ret == 5)//D�γ���ָ�
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
		else if (ret == 6) //E�γ���
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
		else if (ret == 7)//F�γ���
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
		//�ָ����ٶ�ȡ����Ϣ
		ret = JugeErrorPoint(0, 2, key2, 6, key6, OriginalMoney, CopyMoney, OriginalCommonStr, CopyCommonStr);
		if (ret != 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	Hex_Asc(OriginalCommonStr+5,1,blackflag);//��������־
	//�жϹ�����Ϣ���ĺ�������־
/*	if (memcmp(OriginalCommonStr+5, "\x04", 1) == 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_BlackCardErr;
	}
*/
	totalcount = Hex_LongValue(OriginalCommonStr+1, 2);//Ǯ���ۼƽ��״���
	/****************************
	 * ��ȡ���˻�����Ϣ
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
	//��֯���ص��ַ���
	Hex_Asc(Csn, 4, CardInfo);//������
	memcpy(CardInfo+8, citycode, 4);//���д���
	memcpy(CardInfo+12, cardno, 8);//������ˮ��
	memcpy(CardInfo+20, initflag, 2);//���ñ�־
	memcpy(CardInfo+22, IssueDate, 8);//��������
	memcpy(CardInfo+30, ValidDate, 8);//��Ч����
	memcpy(CardInfo+38, UseDate, 8);//��������
	memcpy(CardInfo+46, Deposit, 5);//Ѻ��
	sprintf((char *)CardInfo+51, "%05u", totalcount);//Ǯ���ۼƽ��״���
	memcpy(CardInfo+56, OriginalMoney, 12);//Ǯ�����
	memcpy(CardInfo+68, personinfo, 33);//���˻�����Ϣ 
	memcpy(CardInfo+101, blackflag, 2);//��������־
	memcpy(CardInfo+103, cardtype, 3);//�����
	CardInfo[106] = '\0';
	return 0;
}

int STDMETHODCALLTYPE Modify_Card(int Port, int Transid, unsigned char *CardInfo)
/*******************************************
 ����˵����дM1��Ƭ��Ϣ
 ����ֵ��Port���˿ں�
		   Transid����������
		  CardInfo��д��Ŀ���Ϣ
  ���ֵ����
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//��ҵ����
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//�жϿ����Ƿ�һ��
	if (memcmp(CardInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	//PSAM����λ
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	Sleep(50);
	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	
	if (Transid==1001)//�޸Ŀ��ڻ�����Ϣ
	{
		//����15����Keyb
		Asc_Hex(citycode, 2, key_in);//���д���
		memcpy(key_in+2, Csn, 4);//��Ƭ���к�
		Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
		Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
		memcpy(key_in+12, "\x15", 1);//15������ʶ
		
		//PSAM��������������
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key15, outstr, 6);//15����keyb
		ret = M_1001(4, 15, key15, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==2001)//�޸����ñ�־
	{
		//����1����Keyb
		Asc_Hex(citycode, 2, key_in);//���д���
		memcpy(key_in+2, Csn, 4);//��Ƭ���к�
		Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
		Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
		memcpy(key_in+12, "\x01", 1);//1������ʶ
		
		//PSAM��������������
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key1, outstr, 6);//1����keyb
		ret = M_2001(4, 1, key1, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==3001)//�޸�Ѻ��
	{
		//����1����Keyb
		Asc_Hex(citycode, 2, key_in);//���д���
		memcpy(key_in+2, Csn, 4);//��Ƭ���к�
		Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
		Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
		memcpy(key_in+12, "\x01", 1);//1������ʶ
		
		//PSAM��������������
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key1, outstr, 6);//1����keyb
		ret = M_3001(4, 1, key1, CardInfo+12);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
	}
	if (Transid==4001)//�޸ĺ�������־
	{
		//����6����Keyb
		Asc_Hex(citycode, 2, key_in);//���д���
		memcpy(key_in+2, Csn, 4);//��Ƭ���к�
		Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
		Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
		memcpy(key_in+12, "\x06", 1);//6������ʶ
		
		//PSAM��������������
		ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
		if (ret < 0)
		{
			Dev_beep((HANDLE)icdev, 10);
			Dev_beep((HANDLE)icdev, 10);
			Dev_exit((HANDLE)icdev);
			return ret;
		}
		memcpy(key6, outstr, 6);//6����keyb
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
 ����˵���� M1��Ƭ����Ǯ������
 ����ֵ��Port���˿ں�
		   PurchaseInInfo�����������ַ���
  ���ֵ��PurchaseOutInfo�����ѷ��ص��ַ���
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//��ҵ����
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//�жϿ����Ƿ�һ��
	if (memcmp(PurchaseInInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	
	//PSAM����λ
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
	//��ȡ�ն˱��
	//ѡ��0016�ļ�
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
	Hex_Asc(atr, 6, isamid);//PSAM���ն˱��

	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//����2����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x02", 1);//2��3������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2����keyb
	//����3����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x03", 1);//3������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key3, outstr, 6);//3����keyb
	//����6����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x06", 1);//6������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6����keyb
	//��ȡǮ�����
	ret = GetValue(4, 2, key2, &oldmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//�ж�Ǯ������Ƿ�����ۿ�Ҫ��
	memcpy(temp, PurchaseInInfo+12, 12);//�ۿ���
	temp[12] = '\0';
	purchasemoneyvalue = atol((char *)temp);
	if (purchasemoneyvalue > oldmoneyvalue)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_InsufficiencyErr;
	}
	
	//��д������Ϣ���������׹��̱�־Ϊ01,�ۼƽ��״���++
	ret = WriteTradeOriginalA(4, 6, key6, &totalcount, &curindex);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//Ǯ���ۿ�
	ret = DecMoneyOriginal(4, 2, key2, oldmoneyvalue, purchasemoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д���׼�¼
	memcpy(purchasedate, PurchaseInInfo+24, 8);//��������
	memcpy(purchasetime, PurchaseInInfo+32, 6);//����ʱ��
	ret = WriteRecord(4, key3, curindex, purchasedate, purchasetime, oldmoneyvalue, purchasemoneyvalue, 
		(unsigned char *)"\x06");
	if (ret != 0)
		goto response;
	//��д������Ϣ�������׹���Ϊ02
	ret = WriteTradeOriginalB(4, 6, key6);
	if (ret != 0)
		goto response;

	//����������Ϣ����������
	ret = CopyTrade(4, 6, key6);
	if (ret !=0)
		goto response;
	//����Ǯ������������
	ret = CopyMoney(4, 2, key2);
	if (ret !=0)
		goto response;
response:
	Hex_Asc(Csn, 4, PurchaseOutInfo);//������
	memcpy(PurchaseOutInfo+8, cardid, 12);//����
	sprintf((char *)PurchaseOutInfo+20, "%05u", totalcount);//Ǯ���ۼƽ��״���
	sprintf((char *)PurchaseOutInfo+25, "%012u", oldmoneyvalue);//Ǯ��ԭ��
	sprintf((char *)PurchaseOutInfo+37, "%012u", purchasemoneyvalue);//���׽��
	memcpy(PurchaseOutInfo+49, purchasedate, 8);//��������
	memcpy(PurchaseOutInfo+57, purchasetime, 6);//����ʱ��
	memcpy(PurchaseOutInfo+63, "06", 2);//�������ͱ�ʶ,06��ʾ����
	memcpy(PurchaseOutInfo+65, isamid, 12);//PSAM���ն˱��
	LongValue_Hex(purchasemoneyvalue, 3, indata);//���׽��
	Asc_Hex(purchasedate, 4, indata+3);//�������� 
	Asc_Hex(purchasetime, 3, indata+7);//����ʱ��
	LongValue_Hex(totalcount, 2, indata+10);//Ǯ�����״���
	Asc_Hex(isamid, 6, indata+12);//SAM���ն˻����
	Asc_Hex(cardno, 4, indata+18);
	memcpy(indata+22, "\xFF\xFF", 2);//Ԥ��
	memcpy(indata+24, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
	//����TAC
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
 ����˵���� M1��Ƭ����Ǯ����ֵ
 ����ֵ��Port���˿ں�
		   LoadInInfo����ֵ�����ַ���
  ���ֵ��LoadOutInfo����ֵ���ص��ַ���
  ����ֵ��=0����ʾ�ɹ�
		  !=0�����صĴ������
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
	 * ��1������Ƭ������
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
	Hex_Asc(outstr, 2, citycode);//��ҵ����
	i=Hex_LongValue(outstr+13, 1);
	sprintf((char *)cardtype, "%03d", i);//�����
	Hex_Asc(outstr+4, 4, cardno);//������ˮ��
	Hex_Asc(outstr+8, 4, cardmac);//����֤��
	memcpy(cardid, citycode, 4);
	memcpy(cardid+4, cardno, 8);
	//�жϿ����Ƿ�һ��
	if (memcmp(LoadInInfo, cardid, 12) != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_CardNoErr;
	}
	//PSAM����λ
	ret = Dev_cpureset((HANDLE)icdev, psamid, 4, 3, atr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//��ȡ�ն˱��
	//ѡ��0016�ļ�
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
	Hex_Asc(atr, 6, isamid);//PSAM���ն˱��
	//PSAM��ѡ��DF01
	ret = Card_FileSel(psamid, 0x00, 0x00, "\xDF\x01", 2, (char *)outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//����1����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x01", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1��2��3��6������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key1, outstr, 6);//1����keyb
	//����2����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x02", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1��2��3��6������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key2, outstr, 6);//2����keyb
	//����3����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x03", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1��2��3��6������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key3, outstr, 6);//3����keyb
	//����6����Keyb
	Asc_Hex(citycode, 2, key_in);//���д���
	memcpy(key_in+2, Csn, 4);//��Ƭ���к�
	Asc_Hex(cardno+4, 2, key_in+6);//������ˮ��
	Asc_Hex(cardmac, 4, key_in+8);//��Ƭ��֤��
	memcpy(key_in+12, "\x06", 1);
	//memcpy(key_in+12, "\x01\x02\x03\x06", 4);//1��2��3��6������ʶ
	//PSAM��������������
	ret = Card_CalKey(psamid, 0x01, 0x01, 13, key_in, outstr);
	if (ret < 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(key6, outstr, 6);//6����keyb
	//��ȡǮ�����
	ret = GetValue(4, 2, key2, &oldmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	memcpy(temp, LoadInInfo+12, 12);//��ֵ���
	temp[12] = '\0';
	addmoneyvalue = atol((char *)temp);

	memcpy(temp, LoadInInfo+38, 12);//����ֵ���
	temp[12] = '\0';
	maxmoney = atol((char *)temp);
	if ((oldmoneyvalue + addmoneyvalue) > maxmoney)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return Dev_MoneyOverErr;
	}
	//��д������Ϣ���������׹��̱�־Ϊ01,�ۼƽ��״���++
	ret = WriteTradeOriginalA(4, 6, key6, &totalcount, &curindex);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//Ǯ���ӿ�
	ret = IncMoneyOriginal(4, 2, key2, oldmoneyvalue, addmoneyvalue);
	if (ret != 0)
	{
		Dev_beep((HANDLE)icdev, 10);
		Dev_beep((HANDLE)icdev, 10);
		Dev_exit((HANDLE)icdev);
		return ret;
	}
	//д���׼�¼
	memcpy(adddate, LoadInInfo+24, 8);//��������
	memcpy(addtime, LoadInInfo+32, 6);//����ʱ��
	ret = WriteRecord(4, key3, curindex, adddate, addtime, oldmoneyvalue, addmoneyvalue, 
		(unsigned char *)"\x02");
	if (ret != 0)
		goto response;
	//д��ֵ������Ϣ��¼
	ret = WriteAddRecord(4, 1, key1, 2, key2, oldmoneyvalue, addmoneyvalue, adddate, addtime);
	if (ret != 0)
		goto response;

	//��д������Ϣ�������׹���Ϊ02
	ret = WriteTradeOriginalB(4, 6, key6);
	if (ret != 0)
		goto response;

	//����������Ϣ����������
	ret = CopyTrade(4, 6, key6);
	if (ret !=0)
		goto response;
	//����Ǯ������������
	ret = CopyMoney(4, 2, key2);
	if (ret !=0)
		goto response;
	
response:
	
	memcpy(tac, "00000000", 8);//tac
	Hex_Asc(Csn, 4, LoadOutInfo);//������
	memcpy(LoadOutInfo+8, cardid, 12);//����
	sprintf((char *)LoadOutInfo+20, "%05u", totalcount);//Ǯ���ۼƽ��״���
	sprintf((char *)LoadOutInfo+25, "%012u", oldmoneyvalue);//Ǯ��ԭ��
	sprintf((char *)LoadOutInfo+37, "%012u", addmoneyvalue);//���׽��
	memcpy(LoadOutInfo+49, adddate, 8);//��������
	memcpy(LoadOutInfo+57, addtime, 6);//����ʱ��
	memcpy(LoadOutInfo+63, "02", 2);//�������ͱ�ʶ,02��ʾ��ֵ
	memcpy(LoadOutInfo+65, isamid, 12);//isam���ն˱��
	LongValue_Hex(addmoneyvalue, 3, indata);//���׽��
	Asc_Hex(adddate, 4, indata+3);//�������� 
	Asc_Hex(addtime, 3, indata+7);//����ʱ��
	LongValue_Hex(totalcount, 2, indata+10);//Ǯ�����״���
	Asc_Hex(isamid, 6, indata+12);//SAM���ն˻����
	Asc_Hex(cardno, 4, indata+18);
	memcpy(indata+22, "\xFF\xFF", 2);//Ԥ��
	memcpy(indata+24, "\x80\x00\x00\x00\x00\x00\x00\x00", 8);
	//����TAC
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
 ����˵���� ��ȡ���֤��Ϣ
 ����ֵ��Port �˿ں�
  ���ֵ��name ����
		  sex �Ա�
		   nation ����
		   birth ��������
		   address סַ
		   number ���֤��֤������ 
		  department ���֤��ǩ������ 
		  validdate ��Ч����
  ����ֵ��=0����ʾ�ɹ�
		  <0�����صĴ������
********************************************/
{
	int ret;

	//�򿪶˿�
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
