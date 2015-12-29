// Card_Operate.h : main header file for the CARD_OPERATE DLL
//

#if !defined(AFX_CARD_OPERATE_H__7C776220_FA5C_4E12_9594_E08F93CECC39__INCLUDED_)
#define AFX_CARD_OPERATE_H__7C776220_FA5C_4E12_9594_E08F93CECC39__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CCard_OperateApp
// See Card_Operate.cpp for the implementation of this class
//

class CCard_OperateApp : public CWinApp
{
public:
	CCard_OperateApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CCard_OperateApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CCard_OperateApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

int icdev;
int psamid;//PSAM卡座

char *MAINKEY="\x10\x11\x22\x21\x33\xA1\xAA\x12\x33\x44\x99\x88\xAD\xDC\xA5\xAB";
unsigned char citycode[5];//城市代码
unsigned char cardtype[4];//卡类别
unsigned char initflag[3];//启用标志
unsigned char cardsn[9];//卡序列号
unsigned char cardno[9];//发行流水号
unsigned char cardcrc[3];//块认证码
unsigned char IssueDate[9];//发卡日期
unsigned char ValidDate[9];//有效日期
unsigned char UseDate[9];//启用日期
unsigned char Deposit[6];//押金
unsigned char isamid[13];//isam卡终端编号
int logflag=0;

int STDMETHODCALLTYPE Format_Card(int Port, unsigned char *Hostaddr, unsigned long Hostport,unsigned char *CardInInfo, 
								  unsigned char *CardOutInfo);
int STDMETHODCALLTYPE Clear_Card(int Port, int Mode,unsigned char *Hostaddr, unsigned long Hostport);
int STDMETHODCALLTYPE Read_Card(int Port, unsigned char *CardInfo);
int STDMETHODCALLTYPE Modify_Card(int Port, int Transid, unsigned char *CardInfo);
int STDMETHODCALLTYPE Purchase_Card(int Port, unsigned char *PurchaseInInfo, unsigned char *PurchaseOutInfo);
int STDMETHODCALLTYPE Load_Card(int Port, unsigned char *LoadInInfo, unsigned char *LoadOutInfo);
int STDMETHODCALLTYPE Read_PIDinfo(int Port,char *name, char *sex, char *nation, char *birth, char *address, char *number, 
								   char *department, char *validdate);
int STDMETHODCALLTYPE Read_Card_Psam(int Port, unsigned char *CardInfo);
int STDMETHODCALLTYPE Read_Card_Second_Psam(int Port, unsigned char *CardInfo);
/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_CARD_OPERATE_H__7C776220_FA5C_4E12_9594_E08F93CECC39__INCLUDED_)
