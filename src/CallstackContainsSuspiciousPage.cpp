#include "Check.h"

namespace ThreadChecks {

	CallstackContainsSuspiciousPage::CallstackContainsSuspiciousPage(PConfig pConfig) : ThreadCheck(pConfig) {}

	VOID CallstackContainsSuspiciousPage::Describe ( VOID ) {
		printf ( "* Checking for threads which have private or non-executable memory pages in their callstack\n" );
	}

	ThreadDetection* CallstackContainsSuspiciousPage::Go ( HANDLE hProcess, Thread* pCandidate ) {

		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		char message[512] = { 0 };

		for ( DWORD64 savedRet : *pCandidate->calltrace ) {

			if ( MemTools::PageIsPrivateExecutable ( hProcess, ( PVOID ) savedRet ) ) {
				wsprintfA(message, "Callstack to blocking function contains private and executable memory page: 0x%p", ( PVOID ) savedRet);
				bSuspicious = TRUE;
				break;
			}

			if ( MemTools::PageIsExecutable ( hProcess, ( PVOID ) savedRet ) == FALSE ) {
				wsprintfA ( message, "Callstack to blocking function contains NON-executable memory page: 0x%p", ( PVOID ) savedRet );
				bSuspicious = TRUE;
				break;
			}

		}

		if ( bSuspicious ) {

			return new ThreadDetection (
				"Abnormal Page in Callstack",
				 message,
				 pCandidate->sti.ClientId.UniqueProcess,
				 pCandidate->sti.ClientId.UniqueThread
			);

		}

		return NULL;

	}
}
