#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "misc.hpp"
#include "scans.hpp"

namespace hsb::scanning {


	thread_scan thread_scans::return_address_spoofing = [](process* process, thread* thread) {

	
		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		SIZE_T nRead = 0, s = 0;

		BYTE instructions[4] = { 0x00 };

		BYTE patternJmpDerefRbx[2] = { 0xFF, 0x23 };
		BYTE patternJmpDerefRbp[3] = { 0xFF, 0x65, 0x00 };
		BYTE patternJmpDerefRdi[2] = { 0xFF, 0x27 };
		BYTE patternJmpDerefRsi[2] = { 0xFF, 0x26 };
		BYTE patternJmpDerefR12[4] = { 0x41, 0xff, 0x24, 0x24 };
		BYTE patternJmpDerefR13[4] = { 0x41, 0xff, 0x65, 0x00 };
		BYTE patternJmpDerefR14[3] = { 0x41, 0xff, 0x26 };
		BYTE patternJmpDerefR15[3] = { 0x41, 0xff, 0x27 };

		for (int i = 0; i < thread->calltrace->raw_addresses.size(); i++) {

			bSuccess = ReadProcessMemory(process->handle, (PVOID)thread->calltrace->raw_addresses.at(i), instructions, sizeof(instructions), &nRead);
			if (bSuccess == FALSE)
				goto Cleanup;

			if (memcmp(instructions, patternJmpDerefRbx, sizeof(patternJmpDerefRbx)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefRbp, sizeof(patternJmpDerefRbp)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefRdi, sizeof(patternJmpDerefRdi)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefRsi, sizeof(patternJmpDerefRsi)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefR12, sizeof(patternJmpDerefR12)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefR13, sizeof(patternJmpDerefR13)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefR14, sizeof(patternJmpDerefR14)) == 0)
				bSuspicious = TRUE;
			else if (memcmp(instructions, patternJmpDerefR15, sizeof(patternJmpDerefR15)) == 0)
				bSuspicious = TRUE;

			if (bSuspicious) {

				thread_detection detection;
				detection.name = L"Return Address Spoofing";
				detection.description = std::format(L"Thread {} returns to JMP gadget. Gadget in: {}", thread->tid, misc::string_to_wstring(thread->calltrace->syms.at(i)));
				detection.tid = thread->tid;
				detection.severity = hsb::containers::detections::CRITICAL;

				process->add_detection(detection);

				break;

			}

		}
	Cleanup:

		return;

	};

}