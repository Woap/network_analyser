#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>


#include <netinet/in.h>
#include <net/ethernet.h> // ethernet OK

#include <netinet/ip.h> // ip
#include <netinet/udp.h> // UDP
#include <netinet/tcp.h> // TCP
#include <net/if_arp.h> // OK
// BOOTP DEF
// DNS DEF
// SMTP
// POP
// IMAP
// SCTP
// HTTP
// FTP
// TELNET
// DHCP
// SMTP

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* verbosite */
int verbosite = 0;

struct my_arphdr {
        u_int16_t ar_hrd; /* Hardware Type           */
        u_int16_t ar_pro; /* Protocol Type           */
        u_char ar_hln;    /* Hardware Address Length */
        u_char ar_pln;    /* Protocol Address Length */
        u_int16_t ar_op; /* Operation Code          */
        u_char ar_sha[6];  /* Sender Mac address */
        u_char ar_sip[4];  /* Sender IP address       */
        u_char ar_tha[6];  /* Target Mac address */
        u_char ar_tip[4];  /* Target IP address       */
};


void print_ftp(const u_char *payload, int len)
{
        int i;
        const u_char *ch = payload;

        /* ascii (if printable) */
        ch = payload;
        printf("    ");
        for(i = 0; i < len; i++) {
                if ( (*ch == 0xd) && (*ch+1 == 0xa))
                        printf("\n    ");
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n\n");
        return;

}


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

        int i;
        int gap;
        const u_char *ch;

        /* offset */
        printf("        %05d   ", offset);

        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
                printf("%02x ", *ch);
                ch++;
                /* print extra space after 8th byte for visual aid */
                if (i == 7)
                        printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
                printf(" ");

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        printf("   ");
                }
        }
        printf("   ");

        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n");

        return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

        int len_rem = len;
        int line_width = 16; /* number of bytes per line */
        int line_len;
        int offset = 0;   /* zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
                return;

        /* data fits on one line */
        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset);
                return;
        }

        /* data spans multiple lines */
        for (;; ) {
                /* compute current line length */
                line_len = line_width % len_rem;
                /* print line */
                print_hex_ascii_line(ch, line_len, offset);
                /* compute total remaining */
                len_rem = len_rem - line_len;
                /* shift pointer to remaining bytes to print */
                ch = ch + line_len;
                /* add offset */
                offset = offset + line_width;
                /* check if we have line width chars or less */
                if (len_rem <= line_width) {
                        /* print last line and get out */
                        print_hex_ascii_line(ch, len_rem, offset);
                        break;
                }
        }

        return;
}

void print_ethernetheader(const struct ether_header *ethernet)
{
        printf("   Destination : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]); // NOT OK
        printf("   Source : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]); // NOT OK

}

void print_ipheader(const struct iphdr *ip)
{
        int size_ip;
        size_ip = ip->ihl*4;
        struct in_addr srce_addr;
        srce_addr.s_addr = ip->saddr;
        struct in_addr dsti_addr;
        dsti_addr.s_addr = ip->daddr;


        if ( verbosite >= 2 ) printf("Src : %s, ", inet_ntoa(srce_addr));
        if ( verbosite >= 2 ) printf("Dst : %s\n", inet_ntoa(dsti_addr));
        if ( verbosite == 3 )
        {
                printf("   Version : %d \n",ip->version);
                printf("   Header Length : %d bytes (%d) \n",size_ip,ip->ihl);
                printf("   Differentiated Services Field : %#04x \n",ip->tos );
                printf("   Total Length : %d \n",__builtin_bswap16(ip->tot_len));
                printf("   Identification : %#06x (%d) \n",__builtin_bswap16(ip->id), __builtin_bswap16(ip->id));
                //  printf("    Flags : %#06x \n",);
                printf("   Fragment offset : %d \n",ip->frag_off); // NOT OK
                printf("   Time to live : %d\n",ip->ttl);
                printf("   Header checksum : %#06x \n",__builtin_bswap16(ip->check));

                printf("   Source : %s\n", inet_ntoa(srce_addr));
                printf("   Destination : %s\n", inet_ntoa(dsti_addr));
        }

}

void print_tcpheader(const struct tcphdr *tcp,int tcp_len)
{

        /* define/compute tcp header offset */
        // TOT LEN IP - ip hdr - tcp hdr

        printf("   Source port: %d\n", ntohs(tcp->th_sport));
        printf("   Destination port: %d\n", ntohs(tcp->th_dport));
        printf("   Sequence number : %d \n", (u_int)tcp->th_seq); // NOT OK
        printf("   Acknowledgement number : %d \n", ntohl((u_int)tcp->th_ack)); // NOT OK
        printf("   Header Length : %d bytes \n",tcp->th_off*4);
        printf("   Flags : %#06x \n",tcp->th_flags);
        printf("   Window size value : %d \n",__builtin_bswap16(tcp->th_win));
        printf("   Checksum : %#06x \n",__builtin_bswap16(tcp->th_sum));
        printf("   Urgent pointer : %d \n",tcp->th_urp);


}

void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet)
{
        const u_char *payload;        /* Packet payload */
        int size_tcp = tcp->th_off*4;
        int size_payload;

        if ( tcp_len > 0 )
        {
                if ( ntohs(tcp->th_sport) == 25 || ntohs(tcp->th_dport) == 25 ) {
                        printf("   SMTP \n");
                }
                else if (  ntohs(tcp->th_sport) == 143 || ntohs(tcp->th_dport) == 143 ) {
                        printf("   IMAP \n");
                }
                else if (  ntohs(tcp->th_sport) == 110 || ntohs(tcp->th_dport) == 110 ) {
                        printf("   POP \n");
                }
                else if (  ntohs(tcp->th_sport) == 23 || ntohs(tcp->th_dport) == 23 ) {
                        printf("   TELNET \n");
                }
                else if (  ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ) {
                        printf("\n Hypertext Transfer Protocol (HTTP) \n");
                }
                else if (  ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) == 21 || ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) == 20 ) {
                        printf("\n File Transfer Protocol (FTP) \n");
                }
                else {
                        printf("\n Unknown protocol\n");
                }
        }

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + size_tcp);
        size_payload = ip_tot_len - (size_ip + size_tcp);

        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                print_ftp(payload, size_payload);
        }
}

void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet){
        const u_char *payload;  /* Packet payload */
        int size_payload;

        if (  ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53 ) {

                printf("\n DNS \n");
        }
        else if (( ntohs(udp->uh_sport) == 67 && ntohs(udp->uh_dport) == 68 ) || ( ntohs(udp->uh_sport) == 68 && ntohs(udp->uh_dport) == 67 )) {

                printf("\n Bootstrap Protocol \n");
        }
        else {
                printf("\n Unknown protocol\n");
        }

        /* define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + sizeof(udp));

        /* compute tcp payload (segment) size */
        size_payload = ip_tot_len - (size_ip + sizeof(udp));

        if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
        }
}

void print_udpheader(const struct udphdr *udp)
{

        printf("   Source port: %d\n", ntohs(udp->uh_sport));
        printf("   Destination port: %d\n", ntohs(udp->uh_dport));
        printf("   Length: %d\n", ntohs(udp->uh_ulen));
        printf("   Checksum: %#06x\n",__builtin_bswap16(udp->uh_sum));

}

void print_arpheader(const struct my_arphdr *arp)
{

        switch(ntohs(arp->ar_hrd)) {
        case ARPHRD_ETHER:
                printf("   Hardware type: Ethernet (%d)\n",ntohs(arp->ar_hrd));
                break;
        default:
                printf("   Hardware type: unknown \n");
                break;
        }

        switch(ntohs(arp->ar_pro)) {
        case ETH_P_IP:
                printf("   Protocol type: IPv4 (%#06x)\n",ntohs(arp->ar_pro));
                break;
        default:
                printf("   Protocol type: unknown \n");
                break;
        }

        printf("   Hardware size :  %u\n",arp->ar_hln);
        printf("   Protocol size: %u\n",arp->ar_pln);

        switch(ntohs(arp->ar_op)) {
        case ARPOP_REQUEST:
                printf("   Opcode : ARP request (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_REPLY:
                printf("   Opcode : ARP reply (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_RREQUEST:
                printf("   Opcode : RARP request (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_RREPLY:
                printf("   Opcode : RARP reply (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_InREQUEST:
                printf("   Opcode : InARP request (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_InREPLY:
                printf("   Opcode : InARP reply (%d)\n",ntohs(arp->ar_op));
                break;
        case ARPOP_NAK:
                printf("   Opcode : ARP NAK (%d)\n",ntohs(arp->ar_op));
                break;
        default:
                printf("   Opcode: unknown \n");
                break;
        }

        printf("   Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_sha[0],arp->ar_sha[1],arp->ar_sha[2],arp->ar_sha[3],arp->ar_sha[4],arp->ar_sha[5]);
        printf("   Sender IP address: %d.%d.%d.%d\n",arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);

        printf("   Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_tha[0],arp->ar_tha[1],arp->ar_tha[2],arp->ar_tha[3],arp->ar_tha[4],arp->ar_tha[5]);
        printf("   Target IP address: %d.%d.%d.%d\n",arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3]);

}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

        static int count = 1;

        const struct ether_header *ethernet; /* The ethernet header [1] */
        const struct iphdr *ip;        /* The IP header */
        const struct tcphdr *tcp;      /* The TCP header */
        const struct udphdr *udp;        /* The UDP header */
        const struct my_arphdr *arp;      /* The TCP header */
        const u_char *payload;              /* Packet payload */

        int size_ip;
        int size_tcp;

        int size_payload;

        printf("\n-------------------------------------\n");
        printf("\nPacket number %d:\n", count);
        count++;

        ethernet = (struct ether_header*)(packet);

        if ( verbosite >= 2 )
        { printf(" Ethernet II, ");
          printf("Src: %02x:%02x:%02x:%02x:%02x:%02x, ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
          printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]); }
        if ( verbosite == 3 ) print_ethernetheader(ethernet);

        switch(ntohs(ethernet->ether_type)) {
        case ETHERTYPE_IP:

                if ( verbosite == 3 ) printf("   Type : IPv4 (%#06x) \n", ntohs(ethernet->ether_type));
                ip = (struct iphdr*)(packet + sizeof(struct ether_header));
                size_ip = ip->ihl*4;

                if ( verbosite >= 2 ) printf("\n Internet Protocol Version 4, ");
                print_ipheader(ip);

                switch(ip->protocol ) {
                case IPPROTO_TCP:

                        if ( verbosite == 3 ) printf("   Protocol: TCP (%d)\n",ip->protocol);
                        tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
                        size_tcp = tcp->th_off*4;
                        int tcp_len = __builtin_bswap16(ip->tot_len)-size_ip-size_tcp;

                        if ( verbosite >= 2 ) printf("\n Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d, Ack: %d, Len: %d \n",ntohs(tcp->th_sport),ntohs(tcp->th_dport),(u_int)tcp->th_seq,ntohl(tcp->th_ack),tcp_len);
                        if ( verbosite == 3 ) print_tcpheader(tcp,tcp_len);
                        if ( verbosite == 3 ) print_tcppayload(tcp,tcp_len,size_ip,ntohs(ip->tot_len),packet);

                        return;
                case IPPROTO_UDP:

                        if ( verbosite == 3 ) printf("   Protocol: UDP (%d)\n",ip->protocol);
                        udp = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);

                        if ( verbosite >= 2 ) printf("\n User Datagram Protocol, Src Port: %d, Dst Port: %d \n",ntohs(udp->uh_sport),ntohs(udp->uh_dport));
                        if ( verbosite == 3 ) print_udpheader(udp);
                        if ( verbosite == 3 ) print_udppayload(udp,size_ip,ntohs(ip->tot_len),packet);

                        return;
                case IPPROTO_ICMP:

                        if ( verbosite == 3 ) printf("   Protocol: ICMP (%d)\n",ip->protocol);
                        return;
                case IPPROTO_IP:

                        if ( verbosite == 3 ) printf("   Protocol: IP (%d)\n",ip->protocol);
                        return;
                default:

                        if ( verbosite == 3 ) printf("   Protocol: unknown\n");
                        return;
                }
                break;

        case ETHERTYPE_ARP:

                if ( verbosite == 3 ) printf("   Type : ARP (%#06x) \n", ntohs(ethernet->ether_type));

                payload = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct my_arphdr));
                size_payload = 60 - (sizeof(struct ether_header) + sizeof(struct my_arphdr));

                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("   Padding (%d bytes) :\n", size_payload);
                        if ( verbosite == 3 ) print_payload(payload, size_payload);
                }

                if ( verbosite >= 2 ) printf("\n Address Resolution Protocol \n");
                arp = (struct my_arphdr*)(packet + sizeof(struct ether_header));

                if ( verbosite == 3 ) print_arpheader(arp);

                break;
        case ETHERTYPE_REVARP:
                if ( verbosite == 3 ) printf("   Type : RARP (%#06x) \n", ntohs(ethernet->ether_type));
                break;
        default:
                if ( verbosite == 3 ) printf("   Type: unknown \n");

                break;
        }

}

void usage(char *prog)
{
        fprintf(stderr, "usage: %s ( -i <interface> | -o <fichier> ) [ -f <filtre> ] -v <1..3> \n\t  -i <interface> : interface pour l'analyse live \n\t  -o <fichier> : fichier d'entrée pour l'analyse offline\n\t  * choisir l'un ou l'autre \n\t  [ -f <filtre> ] : filtre BPF (optionnel) \n\t  -v <1..3> : niveau de verbosité (1=très concis ; 2=synthétique ; 3=complet) \n", prog);
}

int main(int argc, char **argv)
{

        // ARGUMENT
        char * progname = argv[0];
        extern char * optarg;
        int c;

        // Gestion arguments
        int iflag=0,oflag=0,fflag=0,vflag=0,errflag=0;
        char interface[1024];
        char fichier[1024];
        char filtre[1024];

        int nb = 0;


        while ((c = getopt(argc, argv, "i:o:f:v:")) != -1)
                switch (c) {
                case 'i':
                        iflag++;
                        strcpy(interface,optarg);
                        nb+=2;
                        break;
                case 'o':
                        oflag++;
                        strcpy(fichier,optarg);
                        nb+=2;
                        break;
                case 'f':
                        fflag++;
                        strcpy(filtre,optarg);
                        nb+=2;
                        break;
                case 'v':
                        vflag++;
                        verbosite=atoi(optarg);
                        nb+=2;
                        break;

                case '?':
                        errflag++;
                        break;
                }

        if (errflag || iflag == oflag || argc != nb+1 || vflag == 0)
        {
                usage(progname);
                return -1;
        }

        printf("Verbosité : %d \n",verbosite);


        char *dev = NULL; /* capture device name */
        char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
        pcap_t *handle; /* packet capture handle */

        char filter_exp[] = "ip"; /* filter expression [3] */
        struct bpf_program fp; /* compiled filter program (expression) */
        bpf_u_int32 mask; /* subnet mask */
        bpf_u_int32 net; /* ip */
        int num_packets = 10; /* number of packets to capture */



        //get network number and mask associated with capture device
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                        dev, errbuf);
                net = 0;
                mask = 0;
        }

        /* print capture info */
        printf("Device: %s\n", interface);
        printf("Number of packets: %d\n", num_packets);

        if ( fflag == 1)
                printf("Filter expression: %s\n", filtre);

        // Online
        /* open capture device */
        if ( iflag == 1 )
        {
                handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
                if (handle == NULL) {
                        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
                        exit(EXIT_FAILURE);
                }

                if (pcap_datalink(handle) != DLT_EN10MB) {
                        fprintf(stderr, "%s is not an Ethernet\n", interface);
                        exit(EXIT_FAILURE);
                }


                if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                                filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }


                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Couldn't install filter %s: %s\n",
                                filter_exp, pcap_geterr(handle));
                        exit(EXIT_FAILURE);
                }


                pcap_loop(handle, num_packets, got_packet, NULL);


                pcap_freecode(&fp);
                pcap_close(handle);
        }
        else
        {


                //Offline
                handle = pcap_open_offline(fichier, errbuf);

                if (handle == NULL) {
                        fprintf(stderr, "Erreur pcap_open_offline (file : %s ) : %s\n", fichier, errbuf);
                        return -1;
                }

                if ( fflag == 1 )
                {
                        if (pcap_compile(handle, &fp, filtre, 0, net) == -1) {
                                fprintf(stderr, "Erreur filtre expression ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }
                else {
                        if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
                                fprintf(stderr, "Erreur filtre expression ( %s ) : %s\n", filtre, pcap_geterr(handle));
                                return -1;
                        }
                }

                if (pcap_setfilter(handle, &fp) == -1) {
                        fprintf(stderr, "Erreur pcap_setfilter : %s\n", pcap_geterr(handle));
                        return -1;
                }

                // Analyse des paquets
                pcap_loop(handle, num_packets, got_packet, NULL);

        }
        printf("\nCapture complete.\n");

        return 0;
}
