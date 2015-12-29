#ifndef _Dev_Error_H_
#define _Dev_Error_H_

#define Dev_Ok					0//����
#define Dev_OpenCommErr			-1//�򿪶������˿ڴ���
#define Dev_CloseCommErr		-2//�رն������˿ڴ���
#define Dev_LoadKeyErr			-3//������Կ����
#define Dev_CardRequestErr		-4//���������
#define Dev_SelectCardErr		-5//ѡ��Ƭ����
#define Dev_CardSearchErr		-6//Ѱ������
#define Dev_AuthErr				-7//��֤�����������
#define Dev_ReadErr				-8//�������ݴ���
#define Dev_WriteErr			-9//д�����ݴ���
#define Dev_ResetErr			-10//��λ��Ƶģ�����
#define Dev_AnticollErr			-11//����ͻ����
#define Dev_HaltErr				-12//��ֹ��Ƭ����
#define Dev_InitValueErr		-13//��ʼ����ֵ����
#define Dev_ReadValueErr		-14//Ǯ����ֵ����
#define Dev_IncrementErr		-15//Ǯ����ֵ����
#define Dev_DecrementErr		-16//Ǯ����ֵ����
#define Dev_RestoreErr			-17//��ֵ�ش�����
#define Dev_TransferErr			-18//��ֵ���ʹ���
#define Dev_CheckErr			-19//��У��ֵУ�����
#define Dev_CardNoErr			-20//���Ų���
#define Dev_CardMacErr			-21//����֤�����
#define Dev_NoUseErr			-22//��δ����
#define Dev_StopErr				-23//����ͣ��
#define Dev_BlackCardErr		-24//�ÿ�Ϊ��������
#define Dev_CardExceedErr		-25//�ÿ��ѹ���Ч��
#define Dev_InsufficiencyErr	-26//Ǯ���ۿ�����
#define Dev_MoneyOverErr		-27//���ڽ����ϳ�ֵ������޶�
#define Dev_CardStatusErr		-28//��״̬�쳣���޷��ָ�
#define Dev_CardNoReponseErr	-31//��Ƭ��Ӧ��
#define Dev_SelectICCnoErr		-32//ѡ��������
#define Dev_CardBadCommandErr	-33//��Ƭ��֧�ָ�����
#define Dev_SetCpuParaErr		-34//����CPU����������
#define Dev_RemoteMachineErr    -100//���ܻ����Ӳ���


#endif	//_Dev_Error_H_