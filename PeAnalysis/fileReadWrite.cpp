#include "fileReadWrite.h"
#define _CRT_SECURE_NO_WARNINGS

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	//打开文件
	FILE * pFlieStream = NULL;
	unsigned int fileSize = 0;
	if ((pFlieStream = fopen(lpszFile, "rb")) == NULL)
	{
		printf("文件打开失败，请检查路径！");
		return 0;
	}
	//读取文件大小
	fseek(pFlieStream, 0, SEEK_END);
	fileSize = ftell(pFlieStream);
	fseek(pFlieStream, 0, SEEK_SET);
	//分配内存
	*pFileBuffer = malloc(fileSize);
	//检查内存状态
	if (!*pFileBuffer)
	{
		printf("内存分配失败,请重试！");
		fclose(pFlieStream);
		return NULL;
	}
	//读取文件到缓冲区
	if (!(fread(*pFileBuffer, fileSize, 1, pFlieStream)))
	{
		printf("文件写入缓冲区失败！");
		free(*pFileBuffer);
		fclose(pFlieStream);
		return NULL;
	}
	fclose(pFlieStream);
	return fileSize;
}

DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ文件标志头不存在！");
		free(pFileBuffer);
		return 0;
	}
	//DOC头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//申请Image大小空间
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!*pImageBuffer)
	{
		printf("%s", "申请ImageBuffer失败！");
		free(*pImageBuffer);
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	//拷贝SizeOfHeaders
	memcpy(*pImageBuffer,pFileBuffer,pOptionHeader->SizeOfHeaders);
	//循环拷贝节到内存对齐中
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((void*)((DWORD)*pImageBuffer + pTempSectionHeader->VirtualAddress), (void*)((DWORD)pFileBuffer + pTempSectionHeader->PointerToRawData), pTempSectionHeader->SizeOfRawData);
		pTempSectionHeader++;
	}
	return pOptionHeader->SizeOfImage;
}

DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
{
	//DOC头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//使用PE结构计算文件大小
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 1; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//申请File大小空间
	*pNewBuffer = (PDWORD)malloc(fileSize);
	if (!*pNewBuffer)
	{
		printf("%s", "申请ImageBuffer失败！");
		free(*pNewBuffer);
		return 0;
	}
	memset(*pNewBuffer, 0, fileSize);
	//拷贝SizeOfHeaders
	memcpy(*pNewBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	//循环拷贝节到内存对齐中
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		memcpy((void*)((DWORD)*pNewBuffer + pTempSectionHeader->PointerToRawData), (void*)((DWORD)pImageBuffer + pTempSectionHeader->VirtualAddress), pTempSectionHeader->SizeOfRawData);
		pTempSectionHeader++;
	}
	return fileSize;
}

BOOL AddImageBufferToShellCode(IN LPVOID pImageBuffer, IN const char* pShellCode, OUT LPVOID* pNewBuffer)
{
//	//计算ShellCode大小
//	size_t shellCodeSize = 0;
//	const char* pNum = pShellCode;
//	while (*pNum++)
//	{
//		shellCodeSize++;
//	}
//	//DOC头
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
//	//NT头
//	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
//	//标准PE头
//	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
//	//可选PE头
//	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
//	//节表解析
//	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
//	//计算空间是否足够
//	DWORD whiteSpaceSize = 0;
//	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		pSectionHeader++;
//		//计算对其前的长度和对其后的长度，判断空白区域是否足够
//		whiteSpaceSize = pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize;
//		if (shellCodeSize + 16 < whiteSpaceSize)
//		{
//			printf("%s: %d  %s %d \n", "节表", i , "空白区域剩余：", whiteSpaceSize);
//			printf("添加代码：%s \n", pShellCode);
//			char* pShellCodeBuffer = (char*)pImageBuffer;
//			whiteSpaceSize = (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress);
//			*pShellCodeBuffer += whiteSpaceSize;
//			printf("添加代码：%s \n", pShellCode);
//		}
//		else
//		{
//			printf("%s: %d  %s \n", "节表", i, "空白区域不足！");
//		}
//	}
//
//	/*
//	VirtualSize：            0x00000200     0001BA9A     [V(VS),内存中大小(对齐前的长度).]
//VirtualAddress：         0x00000204     00001000     [V(VO),内存中偏移(该块的RVA).]
//SizeOfRawData：          0x00000208     0001C000     [R(RS),文件中大小(对齐后的长度).]
//PointerToRawData：       0x0000020c     00001000     [R(RO),文件中偏移.]
//PointerToRelocation：    0x00000210     00000000     [在OBJ文件中使用,重定位的偏移.]
//PointerToLinenumbers：   0x00000214     00000000     [行号表的偏移,提供调试.]
//NumberOfRelocations：    0x00000216     0000         [在OBJ文件中使用,重定位项数目.]
//NumberOfLinenumbers：    0x00000218     0000         [行号表中行号的数目.]
//Characteristics：        0x0000021c     60000020     [标志(块属性):20000000h 40000000h 00000020h ]
//	
//	*/
	return true;
}

#define MessageBoxAToState 0x75031060

BOOL AddFileBufferToShellCode(IN OUT LPVOID pFileBuffer, IN const char* pShellCode, IN size_t ShellCodeSize)
{
	//DOC头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//计算空间是否足够
	DWORD whiteSpaceSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		//计算对其前的长度和对其后的长度，判断空白区域是否足够
		whiteSpaceSize = pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize;
		if (sizeof(*pShellCode) + 16 < whiteSpaceSize)
		{
			printf("%s: %d  %s %d \n", "节表", i, "空白区域剩余：", whiteSpaceSize);
			//开始添加ShellCode
			char* pShellCodeAddress = (char*)pFileBuffer;
			pShellCodeAddress = pShellCodeAddress + (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress) + 22;
			memcpy(pShellCodeAddress, pShellCode, ShellCodeSize);
			//AddCharacterCompressionToMemory(pShellCode, shellCodeSize, pShellCodeBuffer); //如果是字符串用这个
			//计算E8   x = 要跳转的地址 - （E8的地址 + 5）
			int e8CallAddress =  MessageBoxAToState - ((int)(pShellCodeAddress + 0xd) - (int)pFileBuffer + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0x9) = e8CallAddress;
			//计算E9   x = 要跳转的地址 - （E8的地址 + 5）
			int e9CallAddress = (pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase) - ((int)(pShellCodeAddress + 0x12 - (int)pFileBuffer) + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0xe) = e9CallAddress;
			//修改OEP
			pOptionHeader->AddressOfEntryPoint = (pShellCodeAddress - (char*)pFileBuffer);
			pShellCodeAddress = nullptr;
			return true;
		}
		else
		{
			printf("%s: %d  %s \n", "节表", i, "空白区域不足！");
		}
		pSectionHeader++;
	}
	return false;
}



BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	FILE * pFlieStream = NULL;
	unsigned int fileSize = 0;
	if ((pFlieStream = fopen(lpszFile, "wb")) == NULL)
	{
		printf("文件打开失败，请检查路径！");
		return false;
	}
	int ret = fwrite(pMemBuffer, sizeof(char), size, pFlieStream);
	if (ret  = size)
		return	true;
	return false;
}

DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	//DOC头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//代码地址减去程序首地址
	DWORD procedureSite = dwRva - (DWORD)&pFileBuffer;
	//判断是否小于VirtualAddress并且大于VirtualAddress + Misc.VirtualSize
	//然后减去VirtualAddress加上PointerToRawData
	PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		if (procedureSite > pTempSectionHeader->VirtualAddress && procedureSite < (pTempSectionHeader->VirtualAddress + pTempSectionHeader->Misc.VirtualSize))
		{
			procedureSite -= pTempSectionHeader->VirtualAddress += pTempSectionHeader->PointerToRawData;
			return procedureSite;
		}
		pTempSectionHeader++;
	}
	return 0;
}

void PrintPEHeaders(LPVOID* pFileBuffer)
{
	if (*((PWORD)*pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ文件标志头不存在！");
		free(*pFileBuffer);
		return;
	}
	//DOC头
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)*pFileBuffer;
	printf("**********DOC头**********\n");
	printf("MZ标记：%x\n", pDosHeader->e_magic);
	printf("PE文件偏移：%x\n", pDosHeader->e_lfanew);
	if (*((PDWORD)((DWORD)*pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("NT文件标标记不存在！");
		free(*pFileBuffer);
		return;
	}
	//NT头
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)*pFileBuffer + pDosHeader->e_lfanew);
	printf("**********NT头**********\n");
	printf("NT头：%x\n", pNTHeader->Signature);
	//标准PE头
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("**********标准PE头**********\n");
	printf("程序运行支持CPU型号：%x\n", pPEHeader->Machine);
	printf("文件节数：%x\n", pPEHeader->NumberOfSections);
	printf("可选PE头大小：%x\n", pPEHeader->SizeOfOptionalHeader);
	//可选PE头
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("**********可选PE头**********\n");
	printf("说明文件类型：%x\n", pOptionHeader->Magic);
	printf("程序文件入口类型：%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("内存镜像基址：%x\n", pOptionHeader->ImageBase);
	printf("内存对齐：%x\n", pOptionHeader->SectionAlignment);
	printf("文件对齐：%x\n", pOptionHeader->FileAlignment);
	printf("内存PE文件映射尺寸：%x\n", pOptionHeader->SizeOfImage);
	printf("头和节表文件对其后大小：%x\n", pOptionHeader->SizeOfHeaders);
	printf("校验和：%x\n", pOptionHeader->CheckSum);
	printf("初始化时保留的堆栈大小：%x\n", pOptionHeader->SizeOfStackReserve);
	printf("初始化时实际提交的大小：%x\n", pOptionHeader->SizeOfStackCommit);
	printf("初始化时保留的堆大小：%x\n", pOptionHeader->SizeOfHeapReserve);
	printf("初始化时实践提交的大小：%x\n", pOptionHeader->SizeOfHeapCommit);
	printf("目录项数目：%x\n", pOptionHeader->NumberOfRvaAndSizes);

	//节表解析
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//printf("Name: %s\n", pSectionHeader->Name);
	//printf("没有对齐前的真实尺寸: %x\n", pSectionHeader->Misc);
	//printf("节区在内存中的偏移地址: %x\n", pSectionHeader->VirtualAddress);
	//printf("节在文件中对齐后的尺寸: %x\n", pSectionHeader->SizeOfRawData);
	//printf("节区在文件中的偏移: %x\n", pSectionHeader->PointerToRawData);
	//printf("节的属性: %x\n", pSectionHeader->Characteristics);
	printf("\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		printf("节表计数: %d\n", i);
		printf("Name: %s\n", pSectionHeader->Name);
		printf("没有对齐前的真实尺寸: %x\n", pSectionHeader->Misc);
		printf("节区在内存中的偏移地址: %x\n", pSectionHeader->VirtualAddress);
		printf("节在文件中对齐后的尺寸: %x\n", pSectionHeader->SizeOfRawData);
		printf("节区在文件中的偏移: %x\n", pSectionHeader->PointerToRawData);
		printf("节的属性: %x\n", pSectionHeader->Characteristics);
		printf("\n");
		pSectionHeader++;
	}
	free(*pFileBuffer);
}

void AddCharacterCompressionToMemory(IN const char* shellCode, size_t shellCodeSize, OUT char* pFileState)
{
	char buff[1000];
	char temp[3] = { 0 };
	memcpy(buff, shellCode, shellCodeSize);
	for (size_t i = 0; i < shellCodeSize / 2; i++)
	{
		memcpy(temp, buff + i * 2, 2);
		*((unsigned char*)(pFileState)+i) = strtoul(temp, NULL, 16);
	}
}