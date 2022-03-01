#pragma once

struct cStringSpan {
	char* string;
	int length;

	cStringSpan() {
		string = nullptr;
		length = 0;
	}

	cStringSpan(char* _string, int _length) {
		string = _string;
		length = _length;
	}

	cStringSpan(char* _string) {
		string = _string;
		length = 0;
		char curr = string[length];
		while (curr != '\0') {
			length++;
			curr = string[length];
		}

		//printf("CSTRINGSPAN: %s WITH SIZE: %d", string, length);
	}
};