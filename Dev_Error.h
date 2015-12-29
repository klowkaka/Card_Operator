#ifndef _Dev_Error_H_
#define _Dev_Error_H_

#define Dev_Ok					0//正常
#define Dev_OpenCommErr			-1//打开读卡器端口错误
#define Dev_CloseCommErr		-2//关闭读卡器端口错误
#define Dev_LoadKeyErr			-3//下载密钥错误
#define Dev_CardRequestErr		-4//卡请求错误
#define Dev_SelectCardErr		-5//选择卡片错误
#define Dev_CardSearchErr		-6//寻卡错误
#define Dev_AuthErr				-7//验证扇区密码错误
#define Dev_ReadErr				-8//读块数据错误
#define Dev_WriteErr			-9//写块数据错误
#define Dev_ResetErr			-10//复位射频模块错误
#define Dev_AnticollErr			-11//防冲突错误
#define Dev_HaltErr				-12//中止卡片错误
#define Dev_InitValueErr		-13//初始化块值错误
#define Dev_ReadValueErr		-14//钱包读值错误
#define Dev_IncrementErr		-15//钱包增值错误
#define Dev_DecrementErr		-16//钱包减值错误
#define Dev_RestoreErr			-17//块值回传错误
#define Dev_TransferErr			-18//块值传送错误
#define Dev_CheckErr			-19//块校验值校验错误
#define Dev_CardNoErr			-20//卡号不符
#define Dev_CardMacErr			-21//卡认证码错误
#define Dev_NoUseErr			-22//卡未启用
#define Dev_StopErr				-23//卡已停用
#define Dev_BlackCardErr		-24//该卡为黑名单卡
#define Dev_CardExceedErr		-25//该卡已过有效期
#define Dev_InsufficiencyErr	-26//钱包扣款余额不足
#define Dev_MoneyOverErr		-27//卡内金额加上充值额大于限额
#define Dev_CardStatusErr		-28//卡状态异常，无法恢复
#define Dev_CardNoReponseErr	-31//卡片无应答
#define Dev_SelectICCnoErr		-32//选择卡座错误
#define Dev_CardBadCommandErr	-33//卡片不支持该命令
#define Dev_SetCpuParaErr		-34//设置CPU卡参数错误
#define Dev_RemoteMachineErr    -100//加密机连接不上


#endif	//_Dev_Error_H_