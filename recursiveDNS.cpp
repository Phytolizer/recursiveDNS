// recursiveDNS.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

int main(int argc, char** argv)
{
    //if incorrect # of cli
    if (argc != 3) {
        printf("Usage: ./recursiveDNS <lookup addr> <dns server>\n");
        exit(-1);
    }

    //Decide Query Type

    //if IP Query type PTR

    //if host Query type A

    //Query Constructor

    //UDP Sender and Reciever

    //Response Parsing

    //User Output

    printf("%-10s: %-15s\n", "Lookup", argv[1]);
    printf("%-10s: %-15s\n", "Query", "put query info here");
    printf("%-10s: %-15s\n", "Server", argv[2]);
    printf("***********************************\n");
    printf("Connection attempts (timeout 10,000 ms");
    printf("Parsed / legible response");

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
