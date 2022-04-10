// -*- mode: C++; -*-
#pragma once

#include "cStringSpan.hpp"

#include <cstdint>
#include <string>

#define DNS_A 1      /* name -> IP (NORMAL LOOKUP)*/
#define DNS_NS 2     /* name server */
#define DNS_CNAME 5  /* canonical name */
#define DNS_PTR 12   /* IP -> name (REVERSE LOOKUP)*/
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15    /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255  /* all records */
#define MAX_DNS_SIZE 512

#ifdef _WIN32
#define PACKEDSTRUCT(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define PACKEDSTRUCT(x) x __attribute__((packed))
#endif

// define classes & structs here
PACKEDSTRUCT(struct QueryHeader {
    std::uint16_t type;
    std::uint16_t qClass;
});

PACKEDSTRUCT(struct FixedDNSHeader {
    std::uint16_t ID;
    std::uint16_t flags;
    std::uint16_t nQuestions;
    std::uint16_t nAnswers;
    std::uint16_t nAuthority;
    std::uint16_t nAdditional;
});

PACKEDSTRUCT(struct DNSAnswerHeader {
    std::uint16_t type;
    std::uint16_t aClass;
    std::uint32_t ttl;
    std::uint16_t len;
});

PACKEDSTRUCT(struct RR {
    std::uint8_t* name;
    DNSAnswerHeader* header;
    std::uint8_t* record;
});

PACKEDSTRUCT(struct QR {
    std::uint8_t* name;
    QueryHeader* header;
});

struct winsock {

    cStringSpan winsock_download(cStringSpan, cStringSpan);
    void makeDNSQuestion(char*, cStringSpan);
    std::uint16_t getNextWord(char*, int);
    cStringSpan readSock(int);
    cStringSpan formatIP(cStringSpan);
    void cleanAndExit(int);
    std::uint8_t* parseName(unsigned char*, unsigned char*, int*, int);
    std::string typeToString(std::uint16_t);
};
