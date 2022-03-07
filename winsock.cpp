#include "pch.h"
#include "winsock.h"

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

		if (bytesRecieved == -1) {
			if ((end - begin) > 10000) {
				printf("timeout in %d ms\n", end - begin);
			}
			else {
				printf("socket error %d\n", WSAGetLastError());
			}
		}
		else
			break;
	}
	if (bytesRecieved == -1) {
		cleanAndExit(s);
		return cStringSpan();
	}

	printf("response in %d ms with %d bytes\n", end - begin, bytesRecieved);

	if (bytesRecieved < sizeof(FixedDNSHeader)) {
		printf("\t++ invalid reply: packet smaller than fixed DNS header\n");
		cleanAndExit(s);
		return cStringSpan();
	}

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
		printf("\tsucceeded with Rcode = %d\n", Rcode);
	else {
		printf("\tfailed with Rcode = %d\n", Rcode);
		cleanAndExit(s);
		return cStringSpan();
	}

	//check for minsize by adding fixed header, q, a, auth, add to get min packet size 
	u_int minPktSize = sizeof(FixedDNSHeader) + ntohs(dh->nQuestions) * sizeof(QueryHeader) + sizeof(DNSAnwserHeader) * (ntohs(dh->nAnwsers)+ntohs(dh->nAuthority)+ntohs(dh->nAdditional));
	if (minPktSize > MAX_DNS_SIZE) {
		printf("\t++ invalid record: RR value length stretches the anwser beyond packet\n");
		cleanAndExit(s);
		return cStringSpan();
	}

	//define some structs to hold the RR of all the data recieved
	QR* questions = new QR[ntohs(dh->nQuestions)]{};
	RR* anwsers = new RR[ntohs(dh->nAnwsers)]{};
	RR* authority = new RR[ntohs(dh->nAuthority)]{};
	RR* additional = new RR[ntohs(dh->nAdditional)]{};

	//move curr pointer to beginning of questions section
	char* curr = &response[sizeof(FixedDNSHeader)];
	int count = 0;
	//read questions
	for (int i = 0; i < ntohs(dh->nQuestions); i++) {
		if ((curr - response) >= bytesRecieved) {
			printf("\t++ invalid selection: not enough records\n");
			cleanAndExit(s);
			exit(-1);
		}
		questions[i].name = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
		curr += count;
		questions[i].header = (QueryHeader*)curr;
		curr += sizeof(QueryHeader);
		//check for truncated DNSAnwserHeader
		if ((curr - response) > bytesRecieved) {
			printf("\t++ invalid record: truncated RR anwser header\n");
			cleanAndExit(s);
			exit(-1);
		}
	}
	//read anwsers
	int nAnwsers = ntohs(dh->nAnwsers);
	for (int i = 0; i < nAnwsers; i++) {
		if ((curr - response) >= bytesRecieved) {
			printf("\t++ invalid selection: not enough records\n");
			cleanAndExit(s);
			exit(-1);
		}
		anwsers[i].name = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
		curr += count;
		anwsers[i].header = (DNSAnwserHeader*)curr;
		curr += sizeof(DNSAnwserHeader);
		//check for truncated DNSAnwserHeader
		if ((curr - response) > bytesRecieved) {
			printf("\t++ invalid record: truncated RR anwser header\n");
			cleanAndExit(s);
			exit(-1);
		}
		//printf("Header type: %hu class: %hu ttl: %du len: %hu\n", ntohs(anwsers[i].header->type), ntohs(anwsers[i].header->aClass), ntohs(anwsers[i].header->ttl), ntohs(anwsers[i].header->len));
		if (ntohs(anwsers[i].header->type) == 1) {//ip
			//ipv4
			//extract ip address here
			anwsers[i].record = new unsigned char[4];
			for (int j = 0; j < 4; j++) {
				anwsers[i].record[j] = curr[j];
			}
			curr += 4;
		}
		else {
			anwsers[i].record = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
			curr += count;
		}
	}
	//read authority
	int nAuthority = ntohs(dh->nAuthority);
	for (int i = 0; i < nAuthority; i++) {
		if ((curr - response) >= bytesRecieved) {
			printf("\t++ invalid selection: not enough records\n");
			cleanAndExit(s);
			exit(-1);
		}
		authority[i].name = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
		curr += count;
		authority[i].header = (DNSAnwserHeader*)curr;
		curr += sizeof(DNSAnwserHeader);
		//check for truncated DNSAnwserHeader
		if ((curr - response) > bytesRecieved) {
			printf("\t++ invalid record: truncated RR anwser header\n");
			cleanAndExit(s);
			exit(-1);
		}
		if (ntohs(authority[i].header->type) == 1) {
			authority[i].record = new unsigned char[4];
			for (int j = 0; j < 4; j++) {
				authority[i].record[j] = curr[j];
			}
			curr += 4;
		}
		else {
			authority[i].record = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
			curr += count;
		}
	}
	//read additional
	int nAdditional = ntohs(dh->nAdditional);
	for (int i = 0; i < nAdditional; i++) {
		if ((curr - response) >= bytesRecieved) {
			printf("\t++ invalid selection: not enough records\n");
			cleanAndExit(s);
			exit(-1);
		}
		additional[i].name = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
		curr += count;
		additional[i].header = (DNSAnwserHeader*)curr;
		curr += sizeof(DNSAnwserHeader);
		//check for truncated DNSAnwserHeader
		if ((curr - response) > bytesRecieved) {
			printf("\t++ invalid record: truncated RR anwser header\n");
			cleanAndExit(s);
			exit(-1);
		}
		if (ntohs(additional[i].header->type) == 1) {
			additional[i].record = new unsigned char[4];
			for (int j = 0; j < 4; j++) {
				additional[i].record[j] = curr[j];
			}
			curr += 4;
		}
		else {
			additional[i].record = parseName((unsigned char*)curr, (unsigned char*)response, &count, bytesRecieved);
			curr += count;
		}

	}

	//output questions
	printf("\t------------ [questions] ----------\n");
	for (int i = 0; i < ntohs(dh->nQuestions); i++) {
		printf("\t\t%s type %hu class %hu\n", (char*)questions[i].name, ntohs(questions[i].header->type), ntohs(questions[i].header->qClass));
	}
	//output anwsers
	printf("\t------------ [anwsers] ------------\n");
	for (int i = 0; i < ntohs(dh->nAnwsers); i++) {
		if (ntohs(anwsers[i].header->type) == 1)
			printf("\t\t%s %s %hhu.%hhu.%hhu.%hhu TTL = %lu\n", anwsers[i].name, typeToString(ntohs(anwsers[i].header->type)), anwsers[i].record[0], anwsers[i].record[1], anwsers[i].record[2], anwsers[i].record[3], ntohl(anwsers[i].header->ttl));
		else
			printf("\t\t%s %s %s TTL = %hu\n", anwsers[i].name, typeToString(ntohs(anwsers[i].header->type)), anwsers[i].record, ntohl(anwsers[i].header->ttl));
	}
	//output authority
	printf("\t------------ [authority] ----------\n");
	for (int i = 0; i < ntohs(dh->nAuthority); i++) {
		if(ntohs(authority[i].header->type) == 1)
			printf("\t\t%s %s %hhu.%hhu.%hhu.%hhu TTL = %lu\n", authority[i].name, typeToString(ntohs(authority[i].header->type)), authority[i].record[0], authority[i].record[1], authority[i].record[2], authority[i].record[3], ntohl(authority[i].header->ttl));
		else
			printf("\t\t%s %s %s TTL = %hu\n", authority[i].name, typeToString(ntohs(authority[i].header->type)), authority[i].record, ntohl(authority[i].header->ttl));
	}
	//output additional
	printf("\t------------ [additional] ---------\n");
	for (int i = 0; i < ntohs(dh->nAdditional); i++) {
		if(ntohs(additional[i].header->type) == 1)
			printf("\t\t%s %s %hhu.%hhu.%hhu.%hhu TTL = %lu\n", additional[i].name, typeToString(ntohs(additional[i].header->type)), additional[i].record[0], additional[i].record[1], additional[i].record[2], additional[i].record[3], ntohl(additional[i].header->ttl));
		else
			printf("\t\t%s %s %s TTL = %hu\n", additional[i].name, typeToString(ntohs(additional[i].header->type)), additional[i].record, ntohl(additional[i].header->ttl));
	}

	// call cleanup when done with everything and ready to exit program
	cleanAndExit(s);
	return cStringSpan(nullptr, 0);
}

void winsock::cleanAndExit(SOCKET s) {
	closesocket(s);
	WSACleanup();
}

std::string winsock::typeToString(u_short type) {
	switch (type) {
		case DNS_A:
			return "A";
		case DNS_NS:
			return "NS";
		case DNS_CNAME:
			return "CNAME";
		case DNS_PTR:
			return "PTR";
		default:
			return std::to_string(type);
	}
	
}

unsigned char* winsock::parseName(unsigned char* nameBuf, unsigned char* buf, int* count, int responseSize) {
	//take a given string in format nameBuf = 3www6google3com0 in buf create and return a string of it correctly formatted + increment count
	unsigned char* name = new unsigned char[256];
	int namePos = 0;
	bool jump = false;
	int nJumps = 0;

	*count = 1;
	//read in the name from the buffer
	//while not at end of string
	while ((*nameBuf != 0)&&((nameBuf-buf)<responseSize)) {
		//if next request is compressed
		if (*nameBuf >= 0xc0) {
			nJumps++;
			//if jumps more times than # bytes just exit
			if (nJumps > MAX_DNS_SIZE) {
				printf("\t++ invalid record: jump loop\n");
				WSACleanup();
				exit(-1);
			}
			jump = true;
			//check for truncated after 0xc0
			if ((nameBuf - buf) >= responseSize - 1) {
				//printf("%d %d", nameBuf - buf, responseSize - 2);
				printf("\t++ invalid record: truncated jump offset\n");
				WSACleanup();
				exit(-1);
			}
			//black magic here
			//extract offset (from slides?)
			int offset = ((*nameBuf & 0x3f) << 8) + *(nameBuf + 1);
			//printf("offset: %d", offset);
			if ((offset < 0) || (offset > responseSize)) {
				printf("\t++ invalid record: jump beyond packet boundary\n");
				WSACleanup();
				exit(-1);
			}
			if (offset < sizeof(FixedDNSHeader)) {
				printf("\t++ invalid record: jump into fixed DNS header\n");
				WSACleanup();
				exit(-1);
			}
			nameBuf = buf + offset - 1;
		}
		else {
			//not compressed
			name[namePos] = *nameBuf;
			namePos++;
		}
		//move pointer up 1 byte for char read
		nameBuf += 1;
		if (!jump)
			*count = *count + 1;
	}
	if ((nameBuf - buf) >= responseSize) {
		printf("\t++ invalid record: truncated name\n");
		WSACleanup();
		exit(-1);
	}
	//end string nullterminator
	name[namePos] = '\0';
	if (jump)
		//4 bytes 16 bits need to move up in packet bc size of jump?
		*count = *count + 1;

	//change string from '3www6google3com0\0' to www.google.com\0
	//start by looping through string
	int nChars;
	int i, j;
	for (i = 0; i < strlen((const char*)name); i++) {
		//set numchars to first value in string
		nChars = name[i];
		//move nchars characters down overtaking previous byteNum
		for (j = 0; j < nChars; j++) {
			name[i] = name[i + 1];
			i++;
		}
		name[i] = '.';
	}
	//last char to nullptr
	name[i - 1] = '\0';
	return name;
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