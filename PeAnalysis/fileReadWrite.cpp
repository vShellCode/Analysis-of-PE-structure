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

BOOL AddImageBufferToShellCode(IN OUT LPVOID pImageBuffer, IN const char* pShellCode, IN size_t ShellCodeSize)
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
			char* pShellCodeAddress = (char*)pImageBuffer;
			pShellCodeAddress = pShellCodeAddress + (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress) + 22;
			memcpy(pShellCodeAddress, pShellCode, ShellCodeSize);
			//AddCharacterCompressionToMemory(pShellCode, shellCodeSize, pShellCodeBuffer); //������ַ��������
			//����E8   x = Ҫ��ת�ĵ�ַ - ��E8�ĵ�ַ + 5��
			int e8CallAddress = MessageBoxAToState - ((int)(pShellCodeAddress + 0xd) - (int)pImageBuffer + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0x9) = e8CallAddress;
			//����E9   x = Ҫ��ת�ĵ�ַ - ��E8�ĵ�ַ + 5��
			int e9CallAddress = (pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase) - ((int)(pShellCodeAddress + 0x12 - (int)pImageBuffer) + pOptionHeader->ImageBase);
			*(int*)(pShellCodeAddress + 0xe) = e9CallAddress;
			//�޸�OEP
			pOptionHeader->AddressOfEntryPoint = (pShellCodeAddress - (char*)pImageBuffer);
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

BOOL EnlargedNodalRegion(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer, size_t EnlargeSize)
{
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(pImageBuffer);
		return false;
	}
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//�����µĿռ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	for (int i = 1; i < pPEHeader->NumberOfSections; i++)
		pSectionHeader++;
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = Align((pSectionHeader->SizeOfRawData += EnlargeSize) > (pSectionHeader->Misc.VirtualSize += EnlargeSize) ?
		pSectionHeader->SizeOfRawData: pSectionHeader->Misc.VirtualSize, pOptionHeader->SectionAlignment);
	*pNewBuffer = (PDWORD)malloc(pOptionHeader->SizeOfImage + EnlargeSize);
	if (!*pNewBuffer)
	{
		printf("%s", "����������ں�Ŀռ�ʧ�ܣ�");
		free(*pNewBuffer);
		return false;
	}
	memset(*pNewBuffer, 0, pOptionHeader->SizeOfImage);
	memcpy(*pNewBuffer, pImageBuffer, pOptionHeader->SizeOfImage);
	return true;
}

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

BOOL MergingSection(IN OUT LPVOID* pImageBuffer)
{
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)*pImageBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	if (*((PWORD)*pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(pImageBuffer);
		return false;
	}
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	DWORD Max = pSectionHeader->SizeOfRawData > pSectionHeader->Misc.VirtualSize ? pSectionHeader->SizeOfRawData : pSectionHeader->Misc.VirtualSize;
	PIMAGE_SECTION_HEADER pSectionHeader_tmp = pSectionHeader;
	pSectionHeader_tmp += (pPEHeader->NumberOfSections - 1);
	pSectionHeader->SizeOfRawData = pSectionHeader->Misc.VirtualSize = Align(pSectionHeader_tmp->VirtualAddress + Max - pOptionHeader->SizeOfHeaders, pOptionHeader->SectionAlignment);
	pPEHeader->NumberOfSections = 1;

	return true;
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

BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SsectionTableSize)
{
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	//����ռ��Ƿ��㹻
	DWORD whiteSpaceSize = 0;
	//1���ж��Ƿ����㹻�Ŀռ䣬�������һ���ڱ�.

	//�ж�������
	//	SizeOfHeader - (DOS + �������� + PE��� + ��׼PEͷ + ��ѡPEͷ + �Ѵ��ڽڱ�) >= 2���ڱ�Ĵ�С �����ֻ��һ���ڱ����ϵĿռ�Ҳ���ԼӲ��ᱨ�����ǻ��а�ȫ������
	whiteSpaceSize = pNTHeader->OptionalHeader.SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pNTHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER)));
	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER))
	{
		printf("���ݻ�����̫С�޷���ӽڱ�");
		return false;
	}
	//Copyһ���µĽڱ� 
	char* pTmpFile = (char*)pFileBuffer;
	char* pTmpFileCopy = (char*)pFileBuffer;
	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pNTHeader->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));
	//�������ں��� ���һ���ڴ�С��000 (����)
	//�޸�PEͷ�нڵ�����
	pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
	//�޸�sizeOfImage�Ĵ�С
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + SsectionTableSize;
	//��ԭ�����ݵ��������һ���ڵ�����(�ڴ�����������)
	//ʹ��PE�ṹ�����ļ���С
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
	for (DWORD i = 2; i < pPEHeader->NumberOfSections; i++)
		pTempSectionHeaderTo++;
	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
	//����File��С�ռ�
	*pNewBuffer = (PDWORD)malloc(fileSize + SsectionTableSize);
	if (!*pNewBuffer)
	{
		printf("%s", "����ImageBufferʧ�ܣ�");
		free(*pNewBuffer);
		return false;
	}
	memset(*pNewBuffer, 0, fileSize + SsectionTableSize);
	//�����ڱ�����
	PIMAGE_SECTION_HEADER pTempSectionHeaderTo2 = (PIMAGE_SECTION_HEADER)pTmpFileCopy;
	memcpy(pTempSectionHeaderTo2->Name, sectionTable, 4);
	pTempSectionHeaderTo2->Misc.VirtualSize = SsectionTableSize;
	pTempSectionHeaderTo2->VirtualAddress = pTempSectionHeaderTo->VirtualAddress + Align(pTempSectionHeaderTo->Misc.VirtualSize, pNTHeader->OptionalHeader.SectionAlignment);
	pTempSectionHeaderTo2->SizeOfRawData = Align(SsectionTableSize, pNTHeader->OptionalHeader.FileAlignment);
	pTempSectionHeaderTo2->PointerToRawData = pTempSectionHeaderTo->PointerToRawData + Align(pTempSectionHeaderTo->SizeOfRawData, pNTHeader->OptionalHeader.FileAlignment);
	memcpy(*pNewBuffer, pFileBuffer, fileSize);
	return true;
}

BOOL DeleteDarbageDataUnderDOS(IN OUT LPVOID* pFileBuffer)
{
	if (*((PWORD)*pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("MZ�ļ���־ͷ�����ڣ�");
		free(*pFileBuffer);
		return false;
	}
	//DOCͷ
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)*pFileBuffer;
	//NTͷ
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	//��׼PEͷ
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
	//��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//�ڱ����
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	printf("**********DOCͷ**********\n");
	printf("PE��ǣ�%x\n", pDosHeader->e_magic);
	printf("PE�ļ�ƫ�ƣ�%x\n", pDosHeader->e_lfanew);
	if (*((PDWORD)((DWORD)*pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("PE�ļ����ǲ����ڣ�");
		free(*pFileBuffer);
		return false;
	}
	//����PE�ļ������λ��
	memcpy(((CHAR*)*pFileBuffer + sizeof(IMAGE_DOS_HEADER)), ((CHAR*)*pFileBuffer+ pDosHeader->e_lfanew), (pOptionHeader->SizeOfHeaders - pDosHeader->e_lfanew));
	//�޸�e_Ifanewָ���λ��
	pDosHeader->e_lfanew = ((CHAR*)*pFileBuffer + sizeof(IMAGE_DOS_HEADER)) - *pFileBuffer;
	return true;
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

DWORD Align(DWORD size, DWORD ALIGN_BASE)
{
	assert(0 != ALIGN_BASE);
	if (size % ALIGN_BASE)
	{
		size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
	}
	return size;
}