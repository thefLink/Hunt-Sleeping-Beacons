#pragma once

#include <string>
#include <format>
#include <array>
#include <string_view>

namespace hsb::containers::detections{

	enum severity {
		LOW,
		MID,
		HIGH,
		CRITICAL
	};

	struct detection{

		std::wstring name;
		std::wstring description;
		severity severity;

		virtual std::wstring to_string() const = 0;

	};

	static constexpr std::array<std::pair<std::wstring_view, std::wstring_view>, 4> severity_info = { {
		{L"\033[32m", L"LOW"},      // Green for LOW
		{L"\033[33m", L"MID"},      // Yellow for MID
		{L"\033[31m", L"HIGH"},     // Red for HIGH
		{L"\033[35m", L"CRITICAL"}  // Magenta for CRITICAL
	} };

	struct process_detection: public detection {

		std::wstring to_string() const override {

			const auto& [color, severity_str] = severity_info[static_cast<size_t>(severity)];

			return std::format(L"! {}{}{}[0m | {}{}{}[0m | Severity: {}{}{}[0m",
				color, name, L"\033",
				color, description, L"\033",
				color, severity_str, L"\033");
		}

	};

	struct thread_detection: public detection {

		DWORD tid = 0;

		std::wstring to_string() const override {

			const auto& [color, severity_str] = severity_info[static_cast<size_t>(severity)];

			return std::format(L"! Thread {} | {}{}{}[0m | {}{}{}[0m | Severity: {}{}{}[0m",
				tid,
				color, name, L"\033",
				color, description, L"\033",
				color, severity_str, L"\033");

		}

	};
		 

}