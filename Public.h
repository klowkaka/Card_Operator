#ifndef _Public_H_
#define _Public_H_

int STDMETHODCALLTYPE Computer_Crc (unsigned char *Data, unsigned char *Crc, int len);
long STDMETHODCALLTYPE Hex_LongValue (unsigned char *HEX, int HEXLen);
int STDMETHODCALLTYPE LongValue_Hex (long Value, int HEXLen, unsigned char *HEX);
int STDMETHODCALLTYPE Hex_Asc (unsigned char *HEX, int HEXLen, unsigned char *String);
int STDMETHODCALLTYPE Asc_Hex (unsigned char *String, int HEXLen, unsigned char *HEX);
int STDMETHODCALLTYPE XorData (unsigned char *Data1, unsigned char *Data2, unsigned char *Middle, int len);
int STDMETHODCALLTYPE FillString (unsigned char *strBuff, int strLen);
int STDMETHODCALLTYPE Triple3DES (BYTE *Data, BYTE *Key, BYTE *Result);
void STDMETHODCALLTYPE DumpStr (char *data, unsigned long datalen);
#endif