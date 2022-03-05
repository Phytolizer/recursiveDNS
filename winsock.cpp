#include "pch.h"
#include "winsock.h"
#include <vector>

constexpr auto TIMEOUT_MS = 10000;

cStringSpan winsock::winsock_download(cStringSpan host, cStringSpan dnsaddr) {
	WSADATA wsaData;
	//Initialize WinSock; once per program run
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("\tWSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		return cStringSpan(nullptr, 0);
	}

	//determine query type (forward or reverse)
	printf("%-10s: %-15s\n", "Lookup", host.string);
	DWORD IP = inet_addr(host.string);
	bool forward = IP == INADDR_NONE;
	if (!forward)
		host = formatIP(host);

	//format a dns question for the socket
	char packet[MAX_DNS_SIZE] = {};
	int packetSize;
	packetSize = host.length + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);

	//fixed field initialization
	FixedDNSHeader* dh = (FixedDNSHeader*)packet;
	QueryHeader* qh = (QueryHeader*)(packet + packetSize - sizeof(QueryHeader));
	//dh fields
	dh->ID = (u_short)htons(_getpid());
	//TODO: Flag setup
	//initialize to 0
	dh->flags = 0;
	//set individual bits of flags here
	//normal query is all rest 0 -> change for reverse?
	//set RD (recursion desired) to 1
	dh->flags = dh->flags | (1 << 8);
	//now reverse correctly
	dh->flags = htons(dh->flags);
	dh->nQuestions = htons(1);
	dh->nAnwsers = 0;
	dh->nAuthority = 0;
	dh->nAdditional = 0;
	//qh fields
	if (forward)
		qh->type = htons(DNS_A); //requesting ipv4
	else
		qh->type = htons(DNS_PTR); //requesting reverse
	qh->qClass = htons(1); //internet
	makeDNSQuestion((char*)(dh + 1), host);
	//printf("DNSQ: %s\n", (char*)dh + 1);

	//General Printout info here///////////////////////
	int type;
	if (forward)
		type = DNS_A;
	else
		type = DNS_PTR;
	printf("%-10s: %-15s, type %d, TXID 0x%.4X\n", "Query", host.string, type, ntohs(dh->ID));
	printf("%-10s: %-15s\n", "Server", dnsaddr.string);
	printf("***********************************\n");

	//open a DNS socket here to send packet/////////////
	char response[MAX_DNS_SIZE] = {};
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		printf("\tsocket() generated error %d\n", WSAGetLastError());
		WSACleanup();
		return cStringSpan(nullptr, 0);
	}
	//maybe need to bind?
	sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.S_un.S_addr = inet_addr(dnsaddr.string);

	int bytesRecieved;
	size_t begin;
	size_t end;
	
	for (int i = 0; i < 3; i++) {
		printf("Attempt %d with %d bytes... ", i, packetSize);

		if (sendto(s, packet, packetSize, 0, (sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
			printf("\tsendto generated error %d\n", WSAGetLastError());
			WSACleanup();
			return cStringSpan(nullptr, 0);
		}
		begin = clock();
		int destlen = sizeof(dest);
		DWORD recvTimeout = TIMEOUT_MS;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvTimeout, sizeof(timeval));
		bytesRecieved = recvfrom(s, response, MAX_DNS_SIZE, 0, (sockaddr*)&dest, &destlen);
		end = clock();

		if (bytesRecieved == -1)
			printf("timeout in %d ms\n", end - begin);
		else
			break;
	}
	if (bytesRecieved == -1) {
		cleanAndExit(s);
		return cStringSpan();
	}
	printf("response in %d ms with %d bytes\n", end-begin, bytesRecieved);

	////////////////////////////////////////////////////
	//now parse the response by moving the header objects around onto the recieved buffer
	dh = (FixedDNSHeader*)response;
	printf("\tTXID: 0x%.4X flags 0x%.4x questions %d anwsers %d authority %d additional %d\n", ntohs(dh->ID), ntohs(dh->flags), ntohs(dh->nQuestions), ntohs(dh->nAnwsers), ntohs(dh->nAuthority), ntohs(dh->nAdditional));
	//TODO: below + timeout 3x attempts stuff
	//if no timeout and we get a response
	//validate txid
	if (dh->ID != htons(_getpid())) {
		printf("\t++ invalid reply: TXID mismatch, sent 0x%.4X, recieved 0x%.4X\n", _getpid(), ntohs(dh->ID));
		cleanAndExit(s);
		return cStringSpan();
	}
	//output rcode (lowest 4 bits of flags)
	//if rcode != 0 >> failed with Rcode = x
	//else succeeded with Rcode = 0
	u_short Rcode = ntohs(dh->flags) & 0x0f;
	if (Rcode == 0)
		printf("\tsucceeded with Rcode = %d", Rcode);
	else {
		printf("\tfailed with Rcode = %d", Rcode);
		cleanAndExit(s);
		return cStringSpan();
	}
	//output questions
	//output anwsers
	//output authority
	//output additional

	// call cleanup when done with everything and ready to exit program
	cleanAndExit(s);
	return cStringSpan(nullptr, 0);
}

void winsock::cleanAndExit(SOCKET s) {
	closesocket(s);
	WSACleanup();
}

void winsock::makeDNSQuestion(char* buf, cStringSpan host) {
	//oh lord do something nasty here
	//ex. www.google.com -> 0x3 'www' 0x6 'google' 0x3 'com'
	int hostpos = 0;
	int bufpos = 0;
	while (hostpos < host.length) {
		u_short wordSize = getNextWord(host.string + hostpos, host.length - hostpos);
		buf[bufpos++] = (char)wordSize;
		memcpy(buf + bufpos, host.string + hostpos, wordSize);
		bufpos += wordSize;
		hostpos += wordSize + 1;
	}
	buf[bufpos] = 0;

	return;
}

u_short winsock::getNextWord(char* buf, int amtLeft) {
	u_short curr = 0;
	while ((buf[curr] != '.') && (curr < amtLeft)) {
		curr++;
	}
	if (curr < amtLeft) {
		return curr;
	}
	else {
		return amtLeft;
	}
}

cStringSpan winsock::formatIP(cStringSpan host) {
	char del = '.';
	std::vector<char*> delLoc;
	char* newStr = new char[host.length + 13];
	for (int i = 0; i < host.length; i++) {
		if (host.string[i] == del) {
			delLoc.push_back(&host.string[i]);
		}
	}
	int curr = 0;
	for (auto it = delLoc.rbegin(); it != delLoc.rend(); it++) {
		int offset = 1;
		while (((*it)[offset] != '.') && ((*it)[offset] != '\0')) {
			newStr[curr] = (*it)[offset];
			curr++;
			offset++;
		}
		newStr[curr] = '.';
		curr++;
	}
	memcpy(newStr + curr, host.string, delLoc[0] - host.string);
	curr += delLoc[0] - host.string;
	memcpy(newStr + curr, ".in-addr.arpa", 14);

	return cStringSpan(newStr);
}