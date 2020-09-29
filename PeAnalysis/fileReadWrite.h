#pragma once
#include <windows.h>
#include <iostream>

#define MessageBoxAToState 0x75031060




//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);


//**************************************************************************								
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
//参数说明：								
//pFileBuffer  FileBuffer指针								
//pImageBuffer ImageBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);


//**************************************************************************								
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

//**************************************************************************								
//AddImageBufferToShellCode:将ImageBuffer中添加代码								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针
//pShellCodeSize ShellCodeSize大小
//返回值说明：								
//读取失败返回false  否则返回true							
//**************************************************************************								
BOOL AddImageBufferToShellCode(IN OUT LPVOID pImageBuffer, IN const char* pShellCode, IN size_t pShellCodeSize);

//**************************************************************************								
//AddImageBufferToShellCode:将FileBuffer中添加代码								
//参数说明：								
//pFileBuffer FileBuffer指针								
//pNewBuffer NewBuffer指针
//pShellCode ShellCode指针
//返回值说明：								
//读取失败返回false  否则返回true							
//**************************************************************************		
BOOL AddFileBufferToShellCode(IN LPVOID pFileBuffer, IN const char* pShellCode, IN size_t ShellCodeSize);



//**************************************************************************								
//MemeryTOFile:将内存中的数据复制到文件								
//参数说明：								
//pMemBuffer 内存中数据的指针								
//size 要复制的大小								
//lpszFile 要存储的文件路径								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
BOOL MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);

//**************************************************************************								
//RvaToFileOffset:将内存偏移转换为文件偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwRva RVA的值								
//返回值说明：								
//返回转换后的FOA的值  如果失败返回0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);

//**************************************************************************								
//AddImageBufferToShellCode:将FileBuffer中添加节表						
//参数说明：								
//pFileBuffer 文件指针								
//pNewBuffer 新文件指针
//sectionTable 添加节表名
//SsectionTableSize 添加节表大小
//返回值说明：								
//添加失败返回false  否则返回true							
//**************************************************************************	
BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer, IN const char* sectionTable, IN size_t SsectionTableSize);

//**************************************************************************								
//DeleteDarbageDataUnderDOS:删除Dos头下编译器产生垃圾数据，提升节表位置			
//参数说明：								
//*pFileBuffer 文件指针								
//返回值说明：								
//添加失败返回false  否则返回true							
//**************************************************************************	
BOOL DeleteDarbageDataUnderDOS(IN OUT LPVOID* pFileBuffer);

//**************************************************************************	
//**************************************************************************	
//**************************************************************************	
//下方为测试代码
//**************************************************************************	
//**************************************************************************	
//**************************************************************************	

//**************************************************************************								
//PrintPEHeaders:打印节表信息				
//参数说明：								
//LPVOID* pFileBuffer 指针																
//返回值说明：								
//无							
//**************************************************************************		
void PrintPEHeaders(LPVOID* pFileBuffer);

//**************************************************************************								
//PrintPEHeaders:字符压缩到内存	
//参数说明：								
//const char* shellCode 指针			
//size_t shellCodeSize	指针
//char* pFileState		指针
//返回值说明：								
//无							
//**************************************************************************		
void AddCharacterCompressionToMemory(IN const char* shellCode, size_t shellCodeSize, OUT char* pFileState);


#include <assert.h>
//函数功能: 以ALIGN_BASE为对齐度对齐size
//参数说明: 
//		size:需要对齐的大小
//		ALIGN_BASE:对齐度
//返回值:	返回对齐后的大小
DWORD Align(DWORD size, DWORD ALIGN_BASE);
