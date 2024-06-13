#pragma once
#include "windows.h"

namespace TokenTools {

	BOOL IsElevated ( VOID );
	BOOL SetDebugPrivilege ( VOID );

}