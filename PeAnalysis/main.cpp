#include "fileReadWrite.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	//PrintPEHeaders(&pFileBuffer);
	//printf("%d", sizeof(SHELLCODE));
	if (false == AddFileBufferToShellCode(pFileBuffer, SHELLCODE, sizeof(SHELLCODE)))
	{
		printf("%s", "添加ShellCode失败！");
		return 0;
	}
	BOOL blZoo = MemeryToFile(pFileBuffer, fileSize, OUTFILEPATH);
	//LPVOID pMemBuffer = nullptr;
	//int size = CopyFileBufferToImageBuffer(pShelCodeBuffer, &pMemBuffer);

	//LPVOID pNewBuffer = nullptr;
	//size = CopyImageBufferToNewBuffer(pShelCodeBuffer, &pNewBuffer);
	//BOOL blZoo = MemeryToFile(pNewBuffer, fileSize, OUTFILEPATH);
	//return 0;

	//printf("%d", );
}

/*

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


1、Name	8个字节 一般情况下是以"\0"结尾的ASCII吗字符串来标识的名称，内容可以自定义.

注意：该名称并不遵守必须以"\0"结尾的规律，如果不是以"\0"结尾，系统会截取8个字节的长度进行处理.

2、Misc  双字 是该节在没有对齐前的真实尺寸,该值可以不准确。

3、VirtualAddress 节区在内存中的偏移地址。加上ImageBase才是在内存中的真正地址.

4、SizeOfRawData  节在文件中对齐后的尺寸.

5、PointerToRawData 节区在文件中的偏移.

6、PointerToRelocations 在obj文件中使用 对exe无意义

7、PointerToLinenumbers 行号表的位置 调试的时候使用

8、NumberOfRelocations 在obj文件中使用  对exe无意义

9、NumberOfLinenumbers 行号表中行号的数量 调试的时候使用

10、Characteristics 节的属性

*/