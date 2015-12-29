#ifndef _ICCAPP_H_
#define _ICCAPP_H_

#ifdef __cplusplus
extern "C" {
#endif

	int STDMETHODCALLTYPE Card_FileSel (int Psamid, int Type, int Mode, char *FileID, int IDLen, char *OutData);
	int STDMETHODCALLTYPE Card_ReadBin (int Psamid, char *FileID, int Offset, int DataLen, unsigned char *Data);
	int STDMETHODCALLTYPE Card_CalKey (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData);
	int STDMETHODCALLTYPE Card_InitDes (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData);
	int STDMETHODCALLTYPE Card_Des (int Psamid, int P1, int P2, int InLen, unsigned char *InData, unsigned char *OutData);
	int STDMETHODCALLTYPE Card_ComputerTAC (int Psamid, int Len1, unsigned char *Indata1, int Len2, unsigned char *Indata2,
										unsigned char *TAC);
#ifdef __cplusplus
}
#endif


#endif	// _ICCAPP_H_