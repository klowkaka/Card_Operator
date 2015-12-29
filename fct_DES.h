/*******************************************************************************
*                     Copyright (c) Gemplus Card International 1992
*
* Name        : FCT_DES.H
* Description : DES algorithm written in C language
*
* Release     : 1.1
*
* Date        : 05/08/92 Start of development.
* Last Modif  : 01/21/93 Windows Adatation.
********************************************************************************
*
* Warning     :
*
* Remark      :
*
********************************************************************************
*
* VOID function_des (char flag, unsigned char *Data, unsigned char *Key,
*                    unsigned char *Result)
*
*******************************************************************************/
/*******************************************************************************
*
*
*   flag   : CIPHER allows you to use the DES function 
*            DECIPHER allows you to use the DES-1 function 
*   Data   : address of the 8 bytes of data you want to cipher (or decipher)
*   Key    : address of the 8 bytes of the session key
*   Result : address of the 8 bytes of the result
*
*
*******************************************************************************/

#ifndef _FCT_DES_H_
#define _FCT_DES_H_


#define CIPHER    1
#define DECIPHER  2

#ifdef __cplusplus
extern "C" {
#endif

extern void function_des 
(
   unsigned int  Flag,
   BYTE *Data,
   BYTE *Key,
   BYTE *Result
);

#ifdef __cplusplus
}
#endif


#endif	// _FCT_DES_H_
