#include "fileReadWrite.h"

int main()
{
	LPVOID pFileBuffer = NULL;
	int fileSize = ReadPEFile(INFILEPATH, &pFileBuffer);
	//PrintPEHeaders(&pFileBuffer);
	//printf("%d", sizeof(SHELLCODE));
	if (false == AddFileBufferToShellCode(pFileBuffer, SHELLCODE, sizeof(SHELLCODE)))
	{
		printf("%s", "���ShellCodeʧ�ܣ�");
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


1��Name	8���ֽ� һ�����������"\0"��β��ASCII���ַ�������ʶ�����ƣ����ݿ����Զ���.

ע�⣺�����Ʋ������ر�����"\0"��β�Ĺ��ɣ����������"\0"��β��ϵͳ���ȡ8���ֽڵĳ��Ƚ��д���.

2��Misc  ˫�� �Ǹý���û�ж���ǰ����ʵ�ߴ�,��ֵ���Բ�׼ȷ��

3��VirtualAddress �������ڴ��е�ƫ�Ƶ�ַ������ImageBase�������ڴ��е�������ַ.

4��SizeOfRawData  �����ļ��ж����ĳߴ�.

5��PointerToRawData �������ļ��е�ƫ��.

6��PointerToRelocations ��obj�ļ���ʹ�� ��exe������

7��PointerToLinenumbers �кű��λ�� ���Ե�ʱ��ʹ��

8��NumberOfRelocations ��obj�ļ���ʹ��  ��exe������

9��NumberOfLinenumbers �кű����кŵ����� ���Ե�ʱ��ʹ��

10��Characteristics �ڵ�����

*/