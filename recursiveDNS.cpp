// recursiveDNS.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "winsock.h"

int main(int argc, char** argv)
{
    //if incorrect # of cli
    if (argc != 3) {
        printf("Usage: ./recursiveDNS <lookup addr> <dns server>\n");
        exit(-1);
    }

    winsock w;
    cStringSpan host(argv[1]);
    cStringSpan dns(argv[2]);
    w.winsock_download(host, dns);

    //Decide Query Type
    //www.google.com
    //142.251.46.132
    // 
    //if IP Query type PTR

    //if host Query type A

    //Query Constructor
   
    //char a[] = { (char)3, 'w', 'w', 'w', (char)6, 'g', 'o', 'o','g', 'l', 'e', (char)3, 'c','o','m', '\0'};
    //printf("test: %s\n", a);

    //printf("%x\n", (u_short)(1 << 8));
    
    //UDP Sender and Reciever

    //Response Parsing

    //User Output

    //ERRORS TO HANDLE
    /*
        REQUIRED:
        DONE++incorrect TXID
        DONE++packet filled with garbage -> bad txid error?
        DONE++multiple questions?
        DONE++response larger than max dns
        REPORT:
        DONE++invalid reply : packet smaller than fixed DNS header
        ++ invalid section : not enough records(e.g., declared 5 answers but only 3 found)
        DONE++invalid record : jump beyond packet boundary
        ++ invalid record : truncated name(e.g., “6 goog” and the packet ends)
        ++invalid record : truncated RR answer header(i.e., don’t have the full 10 bytes)
        DONE++invalid record : truncated jump offset(e.g., 0xC0 and the packet ends)
        DONE++invalid record : jump into fixed DNS header
        DONE++ invalid record : jump loop
        DONE++ invalid record : RR value length stretches the answer beyond packet
    */
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
