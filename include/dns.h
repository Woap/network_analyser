//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Dated : 29/4/2009

//Header Files
#include <stdio.h> //printf
#include <string.h>    //strlen
#include <stdlib.h>    //malloc
#include <sys/socket.h>    //you know what this is for
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>



//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server


//DNS header structure
struct dns_header
{
        unsigned short id; // identification number
        unsigned short flags;

        unsigned short questions;
        unsigned short answer;
        unsigned short authority;
        unsigned short additional;


};

//Constant sized fields of query structure
struct QUESTION
{
        unsigned short qtype;
        unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
        unsigned short type;
        unsigned short _class;
        unsigned int ttl;
        unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
        unsigned char *name;
        struct R_DATA *resource;
        unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
        unsigned char *name;
        struct QUESTION *ques;
} QUERY;
