#pragma once

#include "Hunt-Sleeping-Beacons.h"
#include "Candidate.h"

#include <string>


class Detection {

public:
	
	Detection(std::string a, std::string b, HANDLE c, HANDLE d) {

		name = a;
		message = b;
		pid = c;
		tid = d;

	}

	Detection(std::string a, std::string b, HANDLE c ) {

		name = a;
		message = b;
		pid = c;

	}

	std::string name;
	std::string message;
	HANDLE pid;
	HANDLE tid;

};

class ThreadDetection : public Detection {

public:

	ThreadDetection(std::string a, std::string b, HANDLE c, HANDLE d) : Detection(a, b, c, d) {};

};

class ProcessDetection : public Detection {

public:

	ProcessDetection(std::string a, std::string b, HANDLE c) : Detection(a, b, c ) {};

};