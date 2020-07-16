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
//AddImageBufferToShellCode:��ImageBuffer����Ӷ������								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��
//pShellCode ShellCodeָ��
//����ֵ˵����								
//��ȡʧ�ܷ���false  ���򷵻�true							
//**************************************************************************								
BOOL AddImageBufferToShellCode(IN LPVOID pImageBuffer, IN const char* pShellCode,OUT LPVOID* pNewBuffer);

//**************************************************************************								
//AddImageBufferToShellCode:��FileBuffer����Ӷ������								
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