#include "fileReadWrite.h"

char INFILEPATH[] = "D:\\PETool 1.0.0.5.exe";

char OUTFILEPATH[] = "D:\\PETool 1.0.0.5(1).exe";

const char SHELLCODE[] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
						   0xE8, 0x00, 0x00, 0x00, 0x00,
						   0xE9, 0x00, 0x00, 0x00, 0x00 };

int main()
{

	//������ӽڱ�հ׽ڴ��� ����Dos��������
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	LPVOID pFileBuffer = NULL;
	int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);

	LPVOID pNewBuffer = nullptr;
	bool bIfOn = DeleteDarbageDataUnderDOS(&pFileBuffer);
	if (!bIfOn)
	{
		printf("%s", "ɾ��Dos����������ʧ�ܣ�");
		return 0;
	}
	if (false == AddFileBufferToSectionTable(pFileBuffer, &pNewBuffer,".tttt", 0x1000))
	{
		printf("%s", "��ӽڱ�ʧ�ܣ�");
		return 0;
	}
	BOOL blZoo = MemeryToFile(pNewBuffer, fileSize + 0x1000, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////



	//������ӽڱ�հ׽ڴ���
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	//LPVOID pFileBuffer = NULL;
	//int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	////PrintPEHeaders(&pFileBuffer);
	////printf("%d", sizeof(SHELLCODE));

	//LPVOID pNewBuffer = nullptr;
	//if (false == AddFileBufferToSectionTable(pFileBuffer, &pNewBuffer,".tttt", 0x1000))
	//{
	//	printf("%s", "��ӽڱ�ʧ�ܣ�");
	//	return 0;
	//}
	//BOOL blZoo = MemeryToFile(pNewBuffer, fileSize + 0x1000, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////


	//����ShellCode��Ӵ���
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	//LPVOID pFileBuffer = NULL;
	//int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	////PrintPEHeaders(&pFileBuffer);
	////printf("%d", sizeof(SHELLCODE));
	//LPVOID pMemBuffer = nullptr;
	//int size = CopyFileBufferToImageBuffer(pFileBuffer, &pMemBuffer);
	//if (false == AddFileBufferToShellCode(pMemBuffer, SHELLCODE, sizeof(SHELLCODE)))
	//{
	//	printf("%s", "���ShellCodeʧ�ܣ�");
	//	return 0;
	//}
	//LPVOID pNewBuffer = nullptr;
	//size = CopyImageBufferToNewBuffer(pMemBuffer, &pNewBuffer);
	//BOOL blZoo = MemeryToFile(pNewBuffer, fileSize, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////

	return 0;
}