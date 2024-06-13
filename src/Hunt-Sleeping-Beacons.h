#pragma once
#include "Phnt.h"
//#include "winternl.h"
//#include <winnt.h>

#include "dbghelp.h"
#include "psapi.h"

#include <algorithm>
#include <stdio.h>
#include <map>
#include <string>
#include <vector>

typedef std::vector<DWORD64> Calltrace;
typedef std::vector<DWORD64> Rettrace;
typedef std::vector<std::string> SymCalltrace;
typedef std::vector<std::string> ModuleCalltrace;

typedef struct Config {

	DWORD dwPid;
	BOOL commandline;
	BOOL ignoreDotnet;
	BOOL stackSpoofing;
	BOOL silent;

} Config, *PConfig;

static PSTR ToLowerA ( PSTR str )
{

	PSTR start = str;

	while ( *str ) {

		if ( *str <= L'Z' && *str >= 'A' ) {
			*str += 32;
		}

		str += 1;

	}

	return start;

}