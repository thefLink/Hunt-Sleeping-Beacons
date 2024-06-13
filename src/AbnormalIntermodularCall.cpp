#include "Check.h"

namespace ThreadChecks {

	AbnormalIntermodularCall::AbnormalIntermodularCall ( PConfig pConfig ) : ThreadCheck ( pConfig ) {}

	VOID AbnormalIntermodularCall::Describe ( VOID ) {
		printf ( "* Checking for abnormal intermodular calls \n" );
	}

	ThreadDetection* AbnormalIntermodularCall::Go ( HANDLE hProcess, Thread* pCandidate ) {

		std::string moduleTmp;
		BOOL bSuccess = FALSE;
		CHAR message[1024] = { 0 };

		if ( pCandidate->calltrace->size ( ) <= 2 )
			goto Cleanup;

		for (int i = 0; i < pCandidate->calltrace->size(); i++) {

			moduleTmp = MemTools::AddressToModuleName(hProcess, ( PVOID ) pCandidate->calltrace->at(i));
			if (!_stricmp(moduleTmp.c_str(), "kernelbase.dll") || !_stricmp(moduleTmp.c_str(), "kernel32.dll")) {

				if (i == pCandidate->calltrace->size() - 2)
					break;

				moduleTmp = MemTools::AddressToModuleName(hProcess, (PVOID)pCandidate->calltrace->at(i + 1));

				if (!_stricmp(moduleTmp.c_str(), "ntdll.dll")) {

					wsprintfA(message, "%s called %s, this indicates module proxying", 
						pCandidate->symcalltrace->at(i + 1).c_str(),
						pCandidate->symcalltrace->at(i).c_str());

					return new ThreadDetection(

						"Abnormal intermodular call",
						message,
						pCandidate->sti.ClientId.UniqueProcess,
						pCandidate->sti.ClientId.UniqueThread

					);

				}

			}

		}

	Cleanup:
		return NULL;

	}
}
