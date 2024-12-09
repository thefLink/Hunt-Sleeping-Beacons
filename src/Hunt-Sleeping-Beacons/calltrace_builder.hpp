#pragma once

#include "dbghelp.h"
#include <string>
#include <memory>
#include "tlhelp32.h"
#include <vector>

#include "phnt.h"
#include "calltrace.hpp"

namespace hsb::containers {

	class calltrace_builder{
	public:
		calltrace_builder();
		~calltrace_builder();
		std::unique_ptr<calltrace> build(HANDLE, HANDLE);
	};

	//implementation
	//================================================================================================

#pragma region constructor and destructor
	calltrace_builder::calltrace_builder()	{}
	calltrace_builder::~calltrace_builder() {}
#pragma endregion

#pragma region public methods
	std::unique_ptr<calltrace> calltrace_builder::build(HANDLE h_process, HANDLE h_thread) {

		CONTEXT context ={0x00};
		STACKFRAME64 stackframe ={0x00};
		PIMAGEHLP_SYMBOL64 pSymbol = NULL;
		PIMAGEHLP_MODULE64 pModInfo = NULL;
		BOOL bSuccess = FALSE, bModuleFound = FALSE;
		char cSymName[256] ={0x00},line[512] ={0};
		DWORD64 dw64Displacement = 0x00;

		auto c = std::make_unique<calltrace>();

		context.ContextFlags = CONTEXT_ALL;
		bSuccess = GetThreadContext(h_thread,&context);
		if(bSuccess == FALSE)
			return nullptr;

		stackframe.AddrPC.Offset = context.Rip;
		stackframe.AddrPC.Mode = AddrModeFlat;
		stackframe.AddrStack.Offset = context.Rsp;
		stackframe.AddrStack.Mode = AddrModeFlat;
		stackframe.AddrFrame.Offset = context.Rbp;
		stackframe.AddrFrame.Mode = AddrModeFlat;

		pSymbol = (PIMAGEHLP_SYMBOL64)LocalAlloc(LMEM_ZEROINIT,sizeof(IMAGEHLP_SYMBOL64) + 256 * sizeof(WCHAR));
		if(pSymbol == NULL)
			return nullptr;

		pModInfo = (PIMAGEHLP_MODULE64)LocalAlloc(LMEM_ZEROINIT,sizeof(IMAGEHLP_MODULE64) + 256 * sizeof(WCHAR));
		if(pModInfo == NULL)
			return nullptr;

		pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
		pSymbol->MaxNameLength = 255;
		pModInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

		while(1) {

			bSuccess = StackWalk64(IMAGE_FILE_MACHINE_AMD64,h_process,h_thread,&stackframe,&context,NULL,NULL,NULL,NULL);
			if(bSuccess == FALSE) {
				break;
			}

			memset(line,0,512);
			memset(cSymName,0,256);

			c->raw_addresses.push_back(stackframe.AddrPC.Offset);

			bModuleFound = SymGetModuleInfo64(h_process,(ULONG64)stackframe.AddrPC.Offset,pModInfo);
			if(bModuleFound == FALSE) {
				c->modules.push_back("unknown");
				c->syms.push_back("unknown");
			}
			else {

				SymGetSymFromAddr64(h_process,(ULONG64)stackframe.AddrPC.Offset,&dw64Displacement,pSymbol);
				UnDecorateSymbolName(pSymbol->Name,cSymName,256,UNDNAME_COMPLETE);

				wsprintfA(line,"%s!%s",pModInfo->ModuleName,cSymName);
				c->syms.push_back(line);
				c->modules.push_back(pModInfo->ModuleName);


			}

		}

		if (pSymbol)
			LocalFree(pSymbol);

		if (pModInfo)
			LocalFree(pModInfo);

		return c;

	}
#pragma endregion


}