#pragma once
#include <windows.h>
#include <iostream>

#define MessageBoxAToState 0x75031060




//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);


//**************************************************************************								
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer								
//����˵����								
//pFileBuffer  FileBufferָ��								
//pImageBuffer ImageBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);


//**************************************************************************								
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

//**************************************************************************								
//AddImageBufferToShellCode:��ImageBuffer����Ӵ���								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��
//pShellCodeSize ShellCodeSize��С
//����ֵ˵����								
//��ȡʧ�ܷ���false  ���򷵻�true							
//**************************************************************************								
BOOL AddImageBufferToShellCode(IN OUT LPVOID pImageBuffer, IN const char* pShellCode, IN size_t pShellCodeSize);

//**************************************************************************								
//AddImageBufferToShellCode:��FileBuffer����Ӵ���								
//����˵����								
//pFileBuffer FileBufferָ��								
//pNewBuffer NewBufferָ��
//pShellCode ShellCodeָ��
//����ֵ˵����								
//��ȡʧ�ܷ���false  ���򷵻�true							
//**************************************************************************		
BOOL AddFileBufferToShellCode(IN LPVOID pFileBuffer, IN const char* pShellCode, IN size_t ShellCodeSize);



//**************************************************************************								
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�								
//����˵����								
//pMemBuffer �ڴ������ݵ�ָ��								
//size Ҫ���ƵĴ�С								
//lpszFile Ҫ�洢���ļ�·��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);

//**************************************************************************								
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwRva RVA��ֵ								
//����ֵ˵����								
//����ת�����FOA��ֵ  ���ʧ�ܷ���0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);

//**************************************************************************								
//AddImageBufferToShellCode:��FileBuffer����ӽڱ�						
//����˵����								
//pFileBuffer �ļ�ָ��								
//pNewBuffer ���ļ�ָ��
//sectionTable ��ӽڱ���
//SsectionTableSize ��ӽڱ��С
//����ֵ˵����								
//���ʧ�ܷ���false  ���򷵻�true							
//**************************************************************************	
BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SsectionTableSize);

//**************************************************************************								
//DeleteDarbageDataUnderDOS:ɾ��Dosͷ�±����������������ݣ������ڱ�λ��			
//����˵����								
//*pFileBuffer �ļ�ָ��								
//����ֵ˵����								
//���ʧ�ܷ���false  ���򷵻�true							
//**************************************************************************	
BOOL DeleteDarbageDataUnderDOS(IN OUT LPVOID* pFileBuffer);

//**************************************************************************	
//**************************************************************************	
//**************************************************************************	
//�·�Ϊ���Դ���
//**************************************************************************	
//**************************************************************************	
//**************************************************************************	

//**************************************************************************								
//PrintPEHeaders:��ӡ�ڱ���Ϣ				
//����˵����								
//LPVOID* pFileBuffer ָ��																
//����ֵ˵����								
//��							
//**************************************************************************		
void PrintPEHeaders(LPVOID* pFileBuffer);

//**************************************************************************								
//PrintPEHeaders:�ַ�ѹ�����ڴ�	
//����˵����								
//const char* shellCode ָ��			
//size_t shellCodeSize	ָ��
//char* pFileState		ָ��
//����ֵ˵����								
//��							
//**************************************************************************		
void AddCharacterCompressionToMemory(IN const char* shellCode, size_t shellCodeSize, OUT char* pFileState);


#include <assert.h>
//��������: ��ALIGN_BASEΪ����ȶ���size
//����˵��: 
//		size:��Ҫ����Ĵ�С
//		ALIGN_BASE:�����
//����ֵ:	���ض����Ĵ�С
DWORD Align(DWORD size, DWORD ALIGN_BASE);
