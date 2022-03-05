#pragma once
#include "cStringSpan.h"
#pragma comment(lib,"ws2_32.lib")

#define DNS_A 1 /* name -> IP (NORMAL LOOKUP)*/
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name (REVERSE LOOKUP)*/
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 
#define MAX_DNS_SIZE 512

#pragma pack(push,1)
//define classes & structs here
struct QueryHeader {
	u_short type;
	u_short qClass;
};

struct FixedDNSHeader {
	u_short ID;
	u_short flags;
	u_short nQuestions;
	u_short nAnwsers;
	u_short nAuthority;
	u_short nAdditional;
};

struct DNSAnwserHeader {
	u_short type;
	u_short aClass;
	u_int ttl;
	u_short len;
};
#pragma pack(pop)

struct winsock {

	cStringSpan winsock_download(cStringSpan, cStringSpan);
	void makeDNSQuestion(char*, cStringSpan);
	u_short getNextWord(char*, int);
	cStringSpan readSock(SOCKET);
	cStringSpan formatIP(cStringSpan);
	void cleanAndExit(SOCKET);
};
