#pragma once
#include "Hunt-Sleeping-Beacons.h"

#include "Candidate.h"
#include "Detection.h"
#include "MemTools.h"
#include "StackTools.h"
#include "ProcessTools.h"


namespace ProcessChecks {

	class ProcessCheck {

	protected:
		PConfig pConfig;

	public:

		virtual VOID Describe(VOID) = 0;
		virtual ProcessDetection* Go(Process*) = 0;

		ProcessCheck(PConfig _pConfig) {
			pConfig = _pConfig;
		}

	};

	typedef struct _SUSPICIOUS_CALLBACK {

		std::string name;
		PVOID addr;

	} SUSPICIOUS_CALLBACK, * PSUSPICIOUS_CALLBACK;


	class EnumerateSuspiciousTimers : public ProcessCheck {

	public:

		EnumerateSuspiciousTimers(PConfig);

		VOID Describe(VOID);
		ProcessDetection* Go(Process*);

	private:

		std::vector<SUSPICIOUS_CALLBACK> SuspiciousCallbacks;

	};

}

namespace ThreadChecks {

	class ThreadCheck {

	protected:
		PConfig pConfig;

	public:

		virtual VOID Describe ( VOID ) = 0;
		virtual ThreadDetection* Go ( HANDLE, Thread* ) = 0;
		
		ThreadCheck( PConfig _pConfig ) {
			pConfig = _pConfig;
		}

	};

	class CallstackContainsSuspiciousPage : public ThreadCheck {

	public:

		CallstackContainsSuspiciousPage(PConfig);

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );

	};

	class CallstackContainsStompedModules : public ThreadCheck {
	public:

		CallstackContainsStompedModules(PConfig);

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );
	};

	class BlockingTimerCallback : public ThreadCheck {
	public:

		BlockingTimerCallback ( PConfig );

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );
		
	private:

		typedef struct CBPARAM {

			PVOID retDispatcher;
			HANDLE hEvent;

		}  CBPARAM, * PCBPARAM;


		BOOL GetCbDispatcher ( PDWORD64 );
		static VOID MyCallback ( PCBPARAM, BOOLEAN );
		DWORD64 OffsetDispatcher;

	};


	class BlockingAPC : public ThreadCheck {
	public:

		BlockingAPC(PConfig);

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );
	private:
		DWORD64 pKiUserApcDispatcher;

	};

	class ReturnAddressSpoofing : public ThreadCheck {
	public:

		ReturnAddressSpoofing ( PConfig );

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );

	};

	class AbnormalIntermodularCall : public ThreadCheck {
	public:

		AbnormalIntermodularCall ( PConfig );

		VOID Describe ( VOID );
		ThreadDetection* Go ( HANDLE, Thread* );

	};

}