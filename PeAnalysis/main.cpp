#include "fileReadWrite.h"

char INFILEPATH[] = "D:\\PETool 1.0.0.5.exe";

char OUTFILEPATH[] = "D:\\PETool 1.0.0.5(1).exe";

const char SHELLCODE[] = { 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
						   0xE8, 0x00, 0x00, 0x00, 0x00,
						   0xE9, 0x00, 0x00, 0x00, 0x00 };

int main()
{

	//测试添加节表空白节代码 清理Dos垃圾数据
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	LPVOID pFileBuffer = NULL;
	int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);

	LPVOID pNewBuffer = nullptr;
	bool bIfOn = DeleteDarbageDataUnderDOS(&pFileBuffer);
	if (!bIfOn)
	{
		printf("%s", "删除Dos下垃圾数据失败！");
		return 0;
	}
	if (false == AddFileBufferToSectionTable(pFileBuffer, &pNewBuffer,".tttt", 0x1000))
	{
		printf("%s", "添加节表失败！");
		return 0;
	}
	BOOL blZoo = MemeryToFile(pNewBuffer, fileSize + 0x1000, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////



	//测试添加节表空白节代码
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	//LPVOID pFileBuffer = NULL;
	//int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	////PrintPEHeaders(&pFileBuffer);
	////printf("%d", sizeof(SHELLCODE));

	//LPVOID pNewBuffer = nullptr;
	//if (false == AddFileBufferToSectionTable(pFileBuffer, &pNewBuffer,".tttt", 0x1000))
	//{
	//	printf("%s", "添加节表失败！");
	//	return 0;
	//}
	//BOOL blZoo = MemeryToFile(pNewBuffer, fileSize + 0x1000, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////


	//测试ShellCode添加代码
	////////////////////////////////////////////////////////////////////////////////////////////////////////
	//LPVOID pFileBuffer = NULL;
	//int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	////PrintPEHeaders(&pFileBuffer);
	////printf("%d", sizeof(SHELLCODE));
	//LPVOID pMemBuffer = nullptr;
	//int size = CopyFileBufferToImageBuffer(pFileBuffer, &pMemBuffer);
	//if (false == AddFileBufferToShellCode(pMemBuffer, SHELLCODE, sizeof(SHELLCODE)))
	//{
	//	printf("%s", "添加ShellCode失败！");
	//	return 0;
	//}
	//LPVOID pNewBuffer = nullptr;
	//size = CopyImageBufferToNewBuffer(pMemBuffer, &pNewBuffer);
	//BOOL blZoo = MemeryToFile(pNewBuffer, fileSize, OUTFILEPATH);
	////////////////////////////////////////////////////////////////////////////////////////////////////////

	return 0;
}