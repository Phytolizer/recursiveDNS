#include "pch.h"
#include "winsock.h"

cStringSpan winsock::winsock_download(cStringSpan host, cStringSpan dnsaddr) {
	WSADATA wsaData;
	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("\tWSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return cStringSpan(nullptr, 0);
	}

	//format a dns question for the socket
	char packet[MAX_DNS_SIZE];
	int packetSize = host.length + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);

	//fixed field initialization
	FixedDNSHeader *dh = (FixedDNSHeader*)packet;
	QueryHeader* qh = (QueryHeader*)(packet + packetSize - sizeof(QueryHeader));
	//dh fields
	dh->ID = (u_short)htons(_getpid());
	//TODO: nani?
	dh->flags = 0;
	dh->nQuestions = htons(1);
	dh->nAnwsers = 0;
	dh->nAuthority = 0;
	dh->nAdditional = 0;
	//qh fields
	qh->type = htons(1); //requesting ipv4
	qh->qClass = htons(1); //internet
	makeDNSQuestion((char*)dh+1, host);
	//printf("DNSQ: %s\n", (char*)dh + 1);

	//open a DNS socket here to send packet/////////////


	////////////////////////////////////////////////////

	// call cleanup when done with everything and ready to exit program
	WSACleanup(); 
	return cStringSpan(nullptr, 0);
}

void winsock::makeDNSQuestion(char* buf, cStringSpan host) {
	//oh lord do something nasty here
	//ex. www.google.com -> 0x3 'www' 0x6 'google' 0x3 'com'
	int hostpos = 0;
	int bufpos = 0;
	while (hostpos < host.length) {
		u_short wordSize = getNextWord(host.string + hostpos, host.length-hostpos);
		buf[bufpos++] = (char)wordSize;
		memcpy(buf + bufpos, host.string + hostpos, wordSize);
		bufpos += wordSize;
		hostpos += wordSize +1;
	}
	buf[bufpos] = 0;
	
	return;
}

u_short winsock::getNextWord(char* buf, int amtLeft) {
	u_short curr = 0;
	while (buf[curr] != '.') {
		curr++;
	}
	if (curr < amtLeft) {
		return curr;
	}
	else {
		return amtLeft;
	}
}