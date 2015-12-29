#include "StdAfx.h"
#include "Stdlib.h"
#include "public.h"
#include "app.h"
#include "dev.h"
#include "dev_error.h"
extern int icdev;
#define RWBUFFLEN			(0x82)	//����һ��������ݳ��ȣ��ֽڣ�

int STDMETHODCALLTYPE Card_FileSel (int Psamid, int Type, int Mode, char *FileID, int IDLen, char *OutData)
/*********************************************************************
˵����	ѡ���ļ������������ļ���EF����Ŀ¼�ļ���ADF����ͨ���ļ���ʶѡ��
������	Type������ѡ�����ͣ�0=MF/1=Ŀ¼/2=�����ļ�/4=Ӧ�û�����
		Mode������������ͣ�0����һ���ļ���2����һ���ļ�
		FileID������2���ַ����ļ���ʶ�����ƴ����磺
			0xEF05��0xDF01�ȣ�
			������������4��Ӧ����Ӧ�û��������ַ������磺
			"sx1.sh.��ᱣ��"��"1PAY.SYS.DDF01"��
		IDLen��FileID�ĳ���
���أ�	0���ɹ�
������	<0��������
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
	memcpy (C_APDU+5, FileID, IDLen);		//data��file tag
	iLen = 5 + IDLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_ReadBin (int Psamid, char *FileID, int Offset, int DataLen, unsigned char *Data)
/*********************************************************************
˵����	��ȡ�����������ļ����ݡ�
������	FileID�������ļ���ʶ�����ƴ���
		Offset�������ȡ������ʼ��ַ��
		DataLen�������ȡ���ݳ��ȡ�
		Data�������ȡ���ݶ����ƴ���ע������㹻�ռ䡣
���أ�	0���ɹ�
������	<0��������
*********************************************************************/
{
	int response, i, j, h, l;
	int iLen, oLen;
	unsigned char R_APDU[RWBUFFLEN+20];
	unsigned char C_APDU[100];

	if ((Offset < 0xff) && (DataLen < RWBUFFLEN))	//�����ݣ�һ���Բ���
	{
		C_APDU[0] = 0x00;						//CLA
		C_APDU[1] = 0xb0;						//INS
		C_APDU[2] = 0x00;	//P1(0x80 + SFI)FileID�����SFI
		C_APDU[3] = Offset & 0xff;				//P2(offset)
		C_APDU[4] = DataLen & 0xff;				//Le(data len)
		iLen = 5;
		oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
		if (oLen < 0)
			return oLen;
		memcpy (Data, R_APDU, oLen-2);		//��������
		return oLen-2;
	}
	else		//�����ݣ��ִβ�������ѡ�ļ�
	{
		//ѡ���ļ�
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
			C_APDU[2] = h & 0xff;	            //P1(��λ��ַ)
			C_APDU[3] = l & 0xff;			    //P2(��λ��ַ)

			if (i == j)		//���һ������
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
˵����	������������
������	Type������ѡ�����ͣ�0=MF/1=Ŀ¼/2=�����ļ�/4=Ӧ�û�����
		Mode������������ͣ�0����һ���ļ���2����һ���ļ�
		FileID������2���ַ����ļ���ʶ�����ƴ����磺
			0xEF05��0xDF01�ȣ�
			������������4��Ӧ����Ӧ�û��������ַ������磺
			"sx1.sh.��ᱣ��"��"1PAY.SYS.DDF01"��
		IDLen��FileID�ĳ���
���أ�	0���ɹ�
������	<0��������
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
	memcpy (C_APDU+5, InData, InLen);		//data��file tag
	iLen = 5 + InLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_InitDes (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData)
/*********************************************************************
˵����	���ܳ�ʼ��
������	Type������ѡ�����ͣ�0=MF/1=Ŀ¼/2=�����ļ�/4=Ӧ�û�����
		Mode������������ͣ�0����һ���ļ���2����һ���ļ�
		FileID������2���ַ����ļ���ʶ�����ƴ����磺
			0xEF05��0xDF01�ȣ�
			������������4��Ӧ����Ӧ�û��������ַ������磺
			"sx1.sh.��ᱣ��"��"1PAY.SYS.DDF01"��
		IDLen��FileID�ĳ���
���أ�	0���ɹ�
������	<0��������
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
	memcpy (C_APDU+5, InData, InLen);		//data��file tag
	iLen = 5 + InLen;
	oLen = Dev_cpuapdu ((HANDLE)icdev, Psamid, iLen, C_APDU, R_APDU);
	if (oLen < 0)
		return oLen;
	memcpy(OutData, R_APDU, oLen-2);
	
	return oLen-2;
}

int STDMETHODCALLTYPE Card_Des (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData)
/*********************************************************************
˵����	����
������	Type������ѡ�����ͣ�0=MF/1=Ŀ¼/2=�����ļ�/4=Ӧ�û�����
		Mode������������ͣ�0����һ���ļ���2����һ���ļ�
		FileID������2���ַ����ļ���ʶ�����ƴ����磺
			0xEF05��0xDF01�ȣ�
			������������4��Ӧ����Ӧ�û��������ַ������磺
			"sx1.sh.��ᱣ��"��"1PAY.SYS.DDF01"��
		IDLen��FileID�ĳ���
���أ�	0���ɹ�
������	<0��������
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
	memcpy (C_APDU+5, InData, InLen);		//data��file tag
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
˵����	����TAC
������	
���أ�	0���ɹ�
������	<0��������
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






