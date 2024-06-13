#include "Check.h"

namespace ThreadChecks {

	ReturnAddressSpoofing::ReturnAddressSpoofing ( PConfig pConfig ) : ThreadCheck ( pConfig ) {}

	VOID ReturnAddressSpoofing::Describe ( VOID ) {
		printf ( "* Checking for threads with a spoofed returnaddress\n" );
	}

	ThreadDetection* ReturnAddressSpoofing::Go ( HANDLE hProcess, Thread* pCandidate ) { 

		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		SIZE_T nRead = 0, s = 0;

		BYTE instructions [ 4 ] = { 0x00 };

		BYTE patternJmpDerefRbx [ 2 ] = { 0xFF, 0x23 };
		BYTE patternJmpDerefRbp [ 3 ] = { 0xFF, 0x65, 0x00 };
		BYTE patternJmpDerefRdi [ 2 ] = { 0xFF, 0x27 };
		BYTE patternJmpDerefRsi [ 2 ] = { 0xFF, 0x26 };
		BYTE patternJmpDerefR12 [ 4 ] = { 0x41, 0xff, 0x24, 0x24 };
		BYTE patternJmpDerefR13 [ 4 ] = { 0x41, 0xff, 0x65, 0x00 };
		BYTE patternJmpDerefR14 [ 3 ] = { 0x41, 0xff, 0x26 };
		BYTE patternJmpDerefR15 [ 3 ] = { 0x41, 0xff, 0x27 };

		for ( int i = 0; i < pCandidate->calltrace->size ( ); i++ ) {

			bSuccess = ReadProcessMemory ( hProcess, ( PVOID ) pCandidate->calltrace->at ( i ), instructions, sizeof ( instructions ), &nRead );
			if ( bSuccess == FALSE )
				goto Cleanup;

			if ( memcmp ( instructions, patternJmpDerefRbx, sizeof ( patternJmpDerefRbx ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefRbp, sizeof ( patternJmpDerefRbp ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefRdi, sizeof ( patternJmpDerefRdi ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefRsi, sizeof ( patternJmpDerefRsi ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefR12, sizeof ( patternJmpDerefR12 ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefR13, sizeof ( patternJmpDerefR13 ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefR14, sizeof ( patternJmpDerefR14 ) ) == 0 )
				bSuspicious = TRUE;
			else if ( memcmp ( instructions, patternJmpDerefR15, sizeof ( patternJmpDerefR15 ) ) == 0 )
				bSuspicious = TRUE;

			if ( bSuspicious ) {

				char message [ 512 ] = { 0 };
				wsprintfA ( message, "Thread continues to JMP gadget after delay. Gadget in: %s", pCandidate->symcalltrace->at ( i ).c_str( ) );

				return new ThreadDetection (
					"Return Address Spoofing",
					message,
					 pCandidate->sti.ClientId.UniqueProcess,
					 pCandidate->sti.ClientId.UniqueThread
				);

			}
		 }

	Cleanup:
		return NULL;

	}
}