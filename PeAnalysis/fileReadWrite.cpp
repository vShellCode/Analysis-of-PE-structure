#include "fileReadWrite.h"
#define _CRT_SECURE_NO_WARNINGS

DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	//���ļ�
	FILE * pFlieStream = NULL;
	unsigned int fileSize = 0;
	if ((pFlieStream = fopen(lpszFile, "rb")) == NULL)
	{
		printf("�ļ���ʧ�ܣ�����·����");
		return 0;
	}
	//��ȡ�ļ���С
	fseek(pFlieStream, 0, SEEK_END);
	fileSize = ftell(pFlieStream);
	fseek(pFlieStream, 0, SEEK_SET);
	//�����ڴ�
	*pFileBuffer = malloc(fileSize);
	//����ڴ�״̬
	if (!*pFileBuffer)
	{
		printf("�ڴ����ʧ��,�����ԣ�");
		fclose(pFlieStream);
		return NULL;
	}
	//��ȡ�ļ���������
	if (!(fread(*pFileBuffer, fileSize, 1, pFlieStream)))
	{
		printf("�ļ�д�뻺����ʧ�ܣ�");
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
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(pFileBuffer);
		return 0;
	}
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//����Image��С�ռ�
	*pImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (!*pImageBuffer)
	{
		printf("%s", "����ImageBufferʧ�ܣ�");
		free(*pImageBuffer);
		return 0;
	}
	memset(*pImageBuffer, 0, pOptionHeader->SizeOfImage);
	//����SizeOfHeaders
	memcpy(*pImageBuffer,pFileBuffer,pOptionHeader->SizeOfHeaders);
	//ѭ�������ڵ��ڴ������
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
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//ʹ��PE�ṹ�����ļ���С
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 1; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//����File��С�ռ�
	*pNewBuffer = (PDWORD)malloc(fileSize);
	if (!*pNewBuffer)
	{
		printf("%s", "����ImageBufferʧ�ܣ�");
		free(*pNewBuffer);
		return 0;
	}
	memset(*pNewBuffer, 0, fileSize);
	//����SizeOfHeaders
	memcpy(*pNewBuffer, pImageBuffer, pOptionHeader->SizeOfHeaders);
	//ѭ�������ڵ��ڴ������
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
//	//����ShellCode��С
//	size_t shellCodeSize = 0;
//	const char* pNum = pShellCode;
//	while (*pNum++)
//	{
//		shellCodeSize++;
//	}
//	//DOCͷ
//	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
//	//NTͷ
//	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
//	//��׼PEͷ
//	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
//	//��ѡPEͷ
//	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
//	//�ڱ����
//	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
//	//����ռ��Ƿ��㹻
//	DWORD whiteSpaceSize = 0;
//	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
//	{
//		pSectionHeader++;
//		//�������ǰ�ĳ��ȺͶ����ĳ��ȣ��жϿհ������Ƿ��㹻
//		whiteSpaceSize = pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize;
//		if (shellCodeSize + 16 < whiteSpaceSize)
//		{
//			printf("%s: %d  %s %d \n", "�ڱ�", i , "�հ�����ʣ�ࣺ", whiteSpaceSize);
//			printf("��Ӵ��룺%s \n", pShellCode);
//			char* pShellCodeBuffer = (char*)pImageBuffer;
//			whiteSpaceSize = (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress);
//			*pShellCodeBuffer += whiteSpaceSize;
//			printf("��Ӵ��룺%s \n", pShellCode);
//		}
//		else
//		{
//			printf("%s: %d  %s \n", "�ڱ�", i, "�հ������㣡");
//		}
//	}
//
//	/*
//	VirtualSize��            0x00000200     0001BA9A     [V(VS),�ڴ��д�С(����ǰ�ĳ���).]
//VirtualAddress��         0x00000204     00001000     [V(VO),�ڴ���ƫ��(�ÿ��RVA).]
//SizeOfRawData��          0x00000208     0001C000     [R(RS),�ļ��д�С(�����ĳ���).]
//PointerToRawData��       0x0000020c     00001000     [R(RO),�ļ���ƫ��.]
//PointerToRelocation��    0x00000210     00000000     [��OBJ�ļ���ʹ��,�ض�λ��ƫ��.]
//PointerToLinenumbers��   0x00000214     00000000     [�кű��ƫ��,�ṩ����.]
//NumberOfRelocations��    0x00000216     0000         [��OBJ�ļ���ʹ��,�ض�λ����Ŀ.]
//NumberOfLinenumbers��    0x00000218     0000         [�кű����кŵ���Ŀ.]
//Characteristics��        0x0000021c     60000020     [��־(������):20000000h 40000000h 00000020h ]
//	
//	*/
	return true;
}

#define MessageBoxAToState 0x75031060

BOOL AddFileBufferToShellCode(IN OUT LPVOID pFileBuffer, IN const char* pShellCode, IN size_t ShellCodeSize)
{
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//����ռ��Ƿ��㹻
	DWORD whiteSpaceSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		//�������ǰ�ĳ��ȺͶ����ĳ��ȣ��жϿհ������Ƿ��㹻
		whiteSpaceSize = pSectionHeader->SizeOfRawData - pSectionHeader->Misc.VirtualSize;
		if (sizeof(*pShellCode) + 16 < whiteSpaceSize)
		{
			printf("%s: %d  %s %d \n", "�ڱ�", i, "�հ�����ʣ�ࣺ", whiteSpaceSize);
			//��ʼ���ShellCode
			char* pShellCodeAddress = (char*)pFileBuffer;
			pShellCodeAddress = pShellCodeAddress + (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress) + 22;
			memcpy(pShellCodeAddress, pShellCode, ShellCodeSize);
			//AddCharacterCompressionToMemory(pShellCode, shellCodeSize, pShellCodeBuffer); //������ַ��������
			//����E8   x = Ҫ��ת�ĵ�ַ - ��E8�ĵ�ַ + 5��
			int e8CallAddress =  MessageBoxAToState - ((int)(pShellCodeAddress + 0xd) - (int)pFileBuffer + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0x9) = e8CallAddress;
			//����E9   x = Ҫ��ת�ĵ�ַ - ��E8�ĵ�ַ + 5��
			int e9CallAddress = (pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase) - ((int)(pShellCodeAddress + 0x12 - (int)pFileBuffer) + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0xe) = e9CallAddress;
			//�޸�OEP
			pOptionHeader->AddressOfEntryPoint = (pShellCodeAddress - (char*)pFileBuffer);
			pShellCodeAddress = nullptr;
			return true;
		}
		else
		{
			printf("%s: %d  %s \n", "�ڱ�", i, "�հ������㣡");
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
		printf("�ļ���ʧ�ܣ�����·����");
		return false;
	}
	int ret = fwrite(pMemBuffer, sizeof(char), size, pFlieStream);
	if (ret  = size)
		return	true;
	return false;
}

DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//�����ַ��ȥ�����׵�ַ
	DWORD procedureSite = dwRva - (DWORD)&pFileBuffer;
	//�ж��Ƿ�С��VirtualAddress���Ҵ���VirtualAddress + Misc.VirtualSize
	//Ȼ���ȥVirtualAddress����PointerToRawData
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
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(*pFileBuffer);
		return;
	}
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)*pFileBuffer;
	printf("**********DOCͷ**********\n");
	printf("MZ��ǣ�%x\n", pDosHeader->e_magic);
	printf("PE�ļ�ƫ�ƣ�%x\n", pDosHeader->e_lfanew);
	if (*((PDWORD)((DWORD)*pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("NT�ļ����ǲ����ڣ�");
		free(*pFileBuffer);
		return;
	}
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)*pFileBuffer + pDosHeader->e_lfanew);
	printf("**********NTͷ**********\n");
	printf("NTͷ��%x\n", pNTHeader->Signature);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	printf("**********��׼PEͷ**********\n");
	printf("��������֧��CPU�ͺţ�%x\n", pPEHeader->Machine);
	printf("�ļ�������%x\n", pPEHeader->NumberOfSections);
	printf("��ѡPEͷ��С��%x\n", pPEHeader->SizeOfOptionalHeader);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	printf("**********��ѡPEͷ**********\n");
	printf("˵���ļ����ͣ�%x\n", pOptionHeader->Magic);
	printf("�����ļ�������ͣ�%x\n", pOptionHeader->AddressOfEntryPoint);
	printf("�ڴ澵���ַ��%x\n", pOptionHeader->ImageBase);
	printf("�ڴ���룺%x\n", pOptionHeader->SectionAlignment);
	printf("�ļ����룺%x\n", pOptionHeader->FileAlignment);
	printf("�ڴ�PE�ļ�ӳ��ߴ磺%x\n", pOptionHeader->SizeOfImage);
	printf("ͷ�ͽڱ��ļ�������С��%x\n", pOptionHeader->SizeOfHeaders);
	printf("У��ͣ�%x\n", pOptionHeader->CheckSum);
	printf("��ʼ��ʱ�����Ķ�ջ��С��%x\n", pOptionHeader->SizeOfStackReserve);
	printf("��ʼ��ʱʵ���ύ�Ĵ�С��%x\n", pOptionHeader->SizeOfStackCommit);
	printf("��ʼ��ʱ�����ĶѴ�С��%x\n", pOptionHeader->SizeOfHeapReserve);
	printf("��ʼ��ʱʵ���ύ�Ĵ�С��%x\n", pOptionHeader->SizeOfHeapCommit);
	printf("Ŀ¼����Ŀ��%x\n", pOptionHeader->NumberOfRvaAndSizes);

	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//printf("Name: %s\n", pSectionHeader->Name);
	//printf("û�ж���ǰ����ʵ�ߴ�: %x\n", pSectionHeader->Misc);
	//printf("�������ڴ��е�ƫ�Ƶ�ַ: %x\n", pSectionHeader->VirtualAddress);
	//printf("�����ļ��ж����ĳߴ�: %x\n", pSectionHeader->SizeOfRawData);
	//printf("�������ļ��е�ƫ��: %x\n", pSectionHeader->PointerToRawData);
	//printf("�ڵ�����: %x\n", pSectionHeader->Characteristics);
	printf("\n");
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		printf("�ڱ����: %d\n", i);
		printf("Name: %s\n", pSectionHeader->Name);
		printf("û�ж���ǰ����ʵ�ߴ�: %x\n", pSectionHeader->Misc);
		printf("�������ڴ��е�ƫ�Ƶ�ַ: %x\n", pSectionHeader->VirtualAddress);
		printf("�����ļ��ж����ĳߴ�: %x\n", pSectionHeader->SizeOfRawData);
		printf("�������ļ��е�ƫ��: %x\n", pSectionHeader->PointerToRawData);
		printf("�ڵ�����: %x\n", pSectionHeader->Characteristics);
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