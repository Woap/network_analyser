/*
 * \file print_functions.c
 * \author IBIS Ibrahim
 *
 * Les fonctions permettant d'analyser et afficher le contenu des différents protocoles.
 * Protocole affichable : Ethernet, IP, TCP, UDP, HTTP, TELNET, ARP, BOOTP/DHCP, FTP, IMAP, SMTP, POP
 *
 */

#include "../include/print_functions.h"

/* Affiche l'entete de tcp */
void print_tcpheader(const struct tcphdr *tcp,int tcp_len,int verbosite,int count)
{
        printf("         ╔═ Source port: %d\n", ntohs(tcp->th_sport));
        printf("         ╠═ Destination port: %d\n", ntohs(tcp->th_dport));
        printf("         ╠═ Sequence number : %d \n", ntohs(tcp->th_seq));
        printf("         ╠═ Acknowledgement number : %d \n",ntohs(tcp->th_ack));
        printf("         ╠═ Header Length : %d bytes \n",tcp->th_off*4);
        printf("         ╠═ Flags : %#05x ( ",tcp->th_flags);
        if (tcp->th_flags & TH_URG) {
                printf("URG ");
        }
        if (tcp->th_flags & TH_ACK) {
                printf("ACK ");
        }
        if (tcp->th_flags & TH_PUSH) {
                printf("PUSH ");
        }
        if (tcp->th_flags & TH_RST) {
                printf("RST ");
        }
        if (tcp->th_flags & TH_SYN) {
                printf("SYN ");
        }
        if (tcp->th_flags & TH_FIN) {
                printf("FIN ");
        }
        printf(")\n");
        printf("         ╠═ Window size value : %d \n",__builtin_bswap16(tcp->th_win));
        printf("         ╠═ Checksum : %#06x \n",__builtin_bswap16(tcp->th_sum));

        int option_size = tcp->th_off*4 - 20;
        if ( option_size )
                printf("         ╠═ Urgent pointer : %d \n",tcp->th_urp);
        else
                printf("         ╚═ Urgent pointer : %d \n",tcp->th_urp);

}

/* Affiche l'entete d'ip */
void print_ipheader(const struct iphdr *ip,int verbosite,int count)
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
                printf("      ╔═ Version : %d \n",ip->version);
                printf("      ╠═ Header Length : %d bytes (%d) \n",size_ip,ip->ihl);
                printf("      ╠═ Differentiated Services Field : %#04x \n",ip->tos );
                printf("      ╠═ Total Length : %d \n",__builtin_bswap16(ip->tot_len));
                printf("      ╠═ Identification : %#06x (%d) \n",__builtin_bswap16(ip->id), __builtin_bswap16(ip->id));
                printf("      ╠═ Fragment offset : %d \n",ip->frag_off);
                printf("      ╠═ Time to live : %d\n",ip->ttl);
                printf("      ╠═ Header checksum : %#06x \n",__builtin_bswap16(ip->check));

                printf("      ╠═ Source : %s\n", inet_ntoa(srce_addr));
                printf("      ╠═ Destination : %s\n", inet_ntoa(dsti_addr));
        }

}

/* Affiche l'entete d'ethernet */
void print_ethernetheader(const struct ether_header *ethernet,int verbosite,int count)
{
        printf("   ╔═ Destination : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
        printf("   ╠═ Source : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
}

/* Affiche l'entete d'udp */
void print_udpheader(const struct udphdr *udp,int verbosite,int count)
{
        printf("        ╔═ Source port: %d\n", ntohs(udp->uh_sport));
        printf("        ╠═ Destination port: %d\n", ntohs(udp->uh_dport));
        printf("        ╠═ Length: %d\n", ntohs(udp->uh_ulen));
        printf("        ╚═ Checksum: %#06x\n",__builtin_bswap16(udp->uh_sum));

}

/* Affiche l'entete d'arp*/
void print_arpheader(const struct my_arphdr *arp,const struct ether_header *ethernet,int verbosite,int count)
{
        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", count);
                printf("Source: %02x:%02x:%02x:%02x:%02x:%02x - ", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
                printf("Destination: %02x:%02x:%02x:%02x:%02x:%02x ", ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                printf("- Protocol : ARP - Length : %d - Info : Who has %d.%d.%d.%d? Tell %d.%d.%d.%d\n",paquet_length,arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3],arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);
        }


        if ( verbosite == 3)
        {
                switch(ntohs(arp->ar_hrd)) {
                case ARPHRD_ETHER:
                        printf("     ╔═ Hardware type: Ethernet (%d)\n",ntohs(arp->ar_hrd));
                        break;
                default:
                        printf("     ╠═ Hardware type: unknown \n");
                        break;
                }

                switch(ntohs(arp->ar_pro)) {
                case ETH_P_IP:
                        printf("     ╠═ Protocol type: IPv4 (%#06x)\n",ntohs(arp->ar_pro));
                        break;
                default:
                        printf("     ╠═ Protocol type: unknown \n");
                        break;
                }

                printf("     ╠═ Hardware size :  %u\n",arp->ar_hln);
                printf("     ╠═ Protocol size: %u\n",arp->ar_pln);

                switch(ntohs(arp->ar_op)) {
                case ARPOP_REQUEST:
                        printf("     ╠═ Opcode : ARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_REPLY:
                        printf("     ╠═ Opcode : ARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_RREQUEST:
                        printf("     ╠═ Opcode : RARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_RREPLY:
                        printf("     ╠═ Opcode : RARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_InREQUEST:
                        printf("     ╠═ Opcode : InARP request (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_InREPLY:
                        printf("     ╠═ Opcode : InARP reply (%d)\n",ntohs(arp->ar_op));
                        break;
                case ARPOP_NAK:
                        printf("     ╠═ Opcode : ARP NAK (%d)\n",ntohs(arp->ar_op));
                        break;
                default:
                        printf("     ╠═ Opcode: unknown \n");
                        break;
                }

                printf("     ╠═ Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_sha[0],arp->ar_sha[1],arp->ar_sha[2],arp->ar_sha[3],arp->ar_sha[4],arp->ar_sha[5]);
                printf("     ╠═ Sender IP address: %d.%d.%d.%d\n",arp->ar_sip[0],arp->ar_sip[1],arp->ar_sip[2],arp->ar_sip[3]);

                printf("     ╠═ Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",arp->ar_tha[0],arp->ar_tha[1],arp->ar_tha[2],arp->ar_tha[3],arp->ar_tha[4],arp->ar_tha[5]);
                printf("     ╚═ Target IP address: %d.%d.%d.%d\n",arp->ar_tip[0],arp->ar_tip[1],arp->ar_tip[2],arp->ar_tip[3]);
        }

}

/* Affiche les champs pour dns */
void print_dns(const u_char *payload, int len,int verbosite,int count)
{
        const struct dns_header *dns;
        dns = (struct dns_header*)(payload);

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                if ( 0x8180 == __builtin_bswap16(dns->flags))
                {
                        printf(" - Protocol : DNS - Length : %d - Info : Standart query response - Transaction ID %#03x \n",paquet_length,__builtin_bswap16(dns->id));
                }
                if ( 0x0100 == __builtin_bswap16(dns->flags))
                {
                        printf(" - Protocol : DNS - Length : %d - Info : Standart query - Transaction ID %#03x \n",paquet_length,__builtin_bswap16(dns->id));
                }
        }

        if ( verbosite == 3)
        {
                printf("           ╠═ Transaction ID : %#03x\n",__builtin_bswap16(dns->id));

                printf("           ╠═ Flags : %#03x ",__builtin_bswap16(dns->flags));
                if ( 0x8180 == __builtin_bswap16(dns->flags))
                {
                        printf("Standard Query Response \n");
                }
                else if ( 0x0100 == __builtin_bswap16(dns->flags))
                {
                        printf("Standard Query \n");
                }
                else
                {
                        printf(" \n");
                }

                printf("           ╠═ Questions: %d\n",__builtin_bswap16(dns->questions));
                printf("           ╠═ Answer RRs: %d\n",__builtin_bswap16(dns->answer));
                printf("           ╠═ Authority RRs: %d\n",__builtin_bswap16(dns->authority));
                printf("           ╠═ Additional RRs: %d\n",__builtin_bswap16(dns->additional));
                printf("           ╠═ Queries\n");

                int queries_answers_size;
                const u_char *queries_answers;
                queries_answers = (u_char *)(payload+ sizeof(struct dns_header));
                queries_answers_size = len-sizeof(struct dns_header);


                const u_char *ch = queries_answers;

                ch = queries_answers;

                char save[1024];
                int size = 0;
                int answer = 0;
                int data_len = 0;
                int k = 0;

                int type_aaaa=0;
                int type_a=0;


                if ( queries_answers_size > 0 )
                {
                        for ( int i = 0; i < queries_answers_size; i++)
                        {
                                if ( *ch == 0xc0 )
                                {
                                        ch++;
                                        i++;
                                        if ( *ch == 0x0c )
                                        {
                                                answer++;
                                                if ( answer == 1)
                                                        printf("           ╠═ Answers\n");
                                                printf("           ╠═ Name : ");
                                                printf("%.*s ", size, save);
                                        }
                                }
                                else
                                {

                                        if ( answer == 0 ) printf("           ╠═ Name : ");

                                        while (*ch != 0x00)
                                        {
                                                if ( k != 0)
                                                {
                                                        if (isprint(*ch))
                                                        {
                                                                if ( answer == 0 ) printf("%c", *ch);
                                                                save[size]=*ch;
                                                                size++;
                                                        }
                                                        else
                                                        {
                                                                if ( answer == 0 ) printf(".");
                                                                save[size]='.';
                                                                size++;
                                                        }
                                                }
                                                k++;
                                                i++;
                                                ch++;
                                        }
                                        k=0;
                                        if ( answer == 0 ) printf(": ");
                                }
                                ch++; i++;
                                ch++; i++;


                                switch (*ch) {
                                case 1: printf("Type A (%d)", *ch); type_a++; break;
                                case 2: printf("Type NS (%d)", *ch); break;
                                case 5: printf("Type CNAME (%d)", *ch); break;
                                case 12: printf("Type PTR (%d)", *ch); break;
                                case 255: printf("Type ANY (%d)", *ch); break;
                                case 28: printf("Type AAAA (%d)", *ch); type_aaaa++; break;
                                case 29: printf("Type LOC (%d)", *ch); break;
                                case 15: printf("Type MX (%d)", *ch); break;
                                case 16: printf("Type TXT (%d)", *ch); break;
                                case 33: printf("Type SRV (%d)", *ch); break;
                                default: printf("Type UNKNOWN (%d)", *ch); break;
                                }

                                ch++; i++;
                                ch++; i++;

                                if ( answer )
                                {
                                        switch (*ch) {
                                        case 1: printf(", Class IN (%#05x), ", *ch); break;
                                        default: printf(", Class UNKNOWN (%d), ", *ch); break;
                                        }
                                }
                                else {
                                        switch (*ch) {
                                        case 1: printf(", Class IN (%#05x)\n", *ch); break;
                                        default: printf(", Class UNKNOWN (%d)\n", *ch); break;
                                        }

                                }

                                if ( answer )
                                {
                                        for ( int j = 0; j < 4; j++)
                                        {
                                                ch++; i++;
                                        }
                                        ch++; i++;
                                        ch++; i++;
                                        data_len = *ch;
                                        if ( !type_a && !type_aaaa)
                                        {
                                                for ( int j = 0; j < data_len; j++)
                                                {
                                                        ch++;
                                                        i++;
                                                        if ( j < data_len-1 && j != 0)
                                                        {
                                                                if (isprint(*ch))
                                                                        printf("%c", *ch);
                                                                else
                                                                        printf(".");
                                                        }
                                                }
                                                //printf("%.*s\n", size, save);
                                                printf("\n");
                                        }
                                        else if ( type_aaaa )
                                        {
                                                printf("addr ");
                                                for ( int j = 0; j < data_len; j++)
                                                {
                                                        if ( j%2 == 0 && j != 0)
                                                                printf(":");
                                                        ch++;
                                                        i++;
                                                        printf("%02x", *ch);


                                                }

                                                printf("\n");
                                        }
                                        else
                                        {
                                                printf("addr ");
                                                for ( int j = 0; j < data_len; j++)
                                                {
                                                        ch++;
                                                        i++;
                                                        printf("%d", *ch);
                                                        if ( j < data_len-1)
                                                                printf(":");


                                                }

                                                printf("\n");
                                        }


                                }
                                ch++;
                                i++;
                                type_aaaa=0;
                                type_a=0;

                        }
                        printf("           ╚═\n");
                }
                else
                {
                        printf("           ╚═\n");
                }
        }

}

/* Affiche les champs pour bootp/dhcp */
void print_bootp(const u_char *payload, int len,int verbosite,int count)
{

        const struct bootp *bootp;
        bootp = (struct bootp*)(payload);

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                printf(" - Protocol : BOOTP/DHCP - Length : %d - Info : DHCP Discover - Transaction ID %#10x \n",paquet_length,__builtin_bswap32(bootp->bp_xid));
        }
        if ( verbosite == 3)
        {
                if ( bootp->bp_op == 1)
                        printf("           ╠═ Message type : Boot Request (%u)\n",bootp->bp_op);
                else
                        printf("           ╠═ Message type : Boot Reply (%u)\n",bootp->bp_op);

                switch (bootp->bp_htype) {
                case HTYPE_ETHERNET: printf("           ╠═ Hardware type : Ethernet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_EXP_ETHERNET: printf("           ╠═ Hardware type : Exp_ethernet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_AX25: printf("           ╠═ Hardware type : AX25 (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_PRONET: printf("           ╠═ Hardware type : Pronet (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_CHAOS: printf("           ╠═ Hardware type : Chaos (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_IEEE802: printf("           ╠═ Hardware type : IEEE802 (%#03x)\n",bootp->bp_htype); break;
                case HTYPE_ARCNET: printf("           ╠═ Hardware type : ArcNet (%#03x)\n",bootp->bp_htype); break;
                default:
                        printf("           ╠═ Hardware type : Unknown (%#03x)\n",bootp->bp_htype); break;
                }

                printf("           ╠═ Hardware address length : %u\n",bootp->bp_hlen);
                printf("           ╠═ Hops : %u\n",bootp->bp_hops);
                printf("           ╠═ Transaction ID : %#10x\n",__builtin_bswap32(bootp->bp_xid));
                printf("           ╠═ Seconds elapsed : %u\n",bootp->bp_secs);
                printf("           ╠═ Bootp flags : %u (Unicast)\n",bootp->bp_flags);
                printf("           ╠═ Client IP address : %s\n",inet_ntoa(bootp->bp_ciaddr));
                printf("           ╠═ Client IP address : %s\n",inet_ntoa(bootp->bp_yiaddr));
                printf("           ╠═ Next server IP address : %s\n",inet_ntoa(bootp->bp_siaddr));
                printf("           ╠═ Relay agent IP address : %s\n",inet_ntoa(bootp->bp_giaddr));
                printf("           ╠═ Client MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",bootp->bp_chaddr[0],bootp->bp_chaddr[1],bootp->bp_chaddr[2],bootp->bp_chaddr[3],bootp->bp_chaddr[4],bootp->bp_chaddr[5]);
                printf("           ╠═ Server name option overloaded by DHCP : %s \n",bootp->bp_sname);
                printf("           ╠═ Boot file name option overloaded by DHCP : %s \n", bootp->bp_file);
                printf("           ╠═ Magic Cookie : (%02x%02x%02x%02x) DHCP \n", bootp->bp_vend[0],bootp->bp_vend[1],bootp->bp_vend[2],bootp->bp_vend[3]);


                int option_size;
                const u_char *vendor;
                vendor = (u_char *)(bootp->bp_vend+4);
                option_size = len-236-4;

                const u_char *ch = vendor;
                int eol=0;

                if ( option_size > 0 )
                {
                        for ( int i = 0; i < option_size; i++)
                        {
                                switch ((int)*ch) {
                                case 50: printf( "           ╠═ Option: (%d) Requested IP address \n",*ch); break;
                                case 51: printf( "           ╠═ Option: (%d) Ip Address Lease Time \n",*ch); break;
                                case 52: printf( "           ╠═ Option: (%d) Option overload \n",*ch); break;
                                case 53: printf( "           ╠═ Option: (%d) Message Type \n",*ch); break;
                                case 54: printf( "           ╠═ Option: (%d) Server ID \n",*ch); break;
                                case 55: printf( "           ╠═ Option: (%d) Parameter List \n",*ch); break;
                                case 56: printf( "           ╠═ Option: (%d)  Message \n",*ch); break;
                                case 57: printf( "           ╠═ Option: (%d) Max Msg Size\n",*ch); break;
                                case 58: printf( "           ╠═ Option: (%d) Renewal Time \n",*ch); break;
                                case 59: printf( "           ╠═ Option: (%d) Rebinding Time \n",*ch); break;
                                case 60: printf( "           ╠═ Option: (%d) Class ID \n",*ch); break;
                                case 61: printf( "           ╠═ Option: (%d) Client ID \n",*ch); break;
                                case 12: printf( "           ╠═ Option: (%d) Hostname \n",*ch); break;
                                case 15: printf( "           ╠═ Option: (%d) Domain name \n",*ch); break;
                                case 44: printf( "           ╠═ Option: (%d) Netbios over TCP/IP name server \n",*ch); break;
                                case 47: printf( "           ╠═ Option: (%d) Netbios over TCP/IP scope \n",*ch); break;
                                case 28: printf( "           ╠═ Option: (%d) Broadcast address \n",*ch); break;
                                case 255: printf( "           ╚═ Option: (%d) End \n",*ch); eol=1; break;
                                case 0: printf( "           ╠═ Option: (%d) Padding \n",*ch); eol=1; break;
                                case 1: printf( "           ╠═ Option: (%d) Subnet Mask \n",*ch); break;
                                case 2: printf( "           ╠═ Option: (%d) Time offset \n",*ch); break;
                                case 3: printf( "           ╠═ Option: (%d) Router\n",*ch); break;
                                case 6: printf( "           ╠═ Option: (%d) DNS\n",*ch); break;
                                default:
                                        printf("           ╠═ Option: (%d) Unknown \n",*ch);
                                        break;
                                }

                                if ( eol == 0)
                                {
                                        ch++;
                                        int len = (int)*ch;
                                        ch++;
                                        i++;
                                        for ( int j = 0; j < len; j++)
                                        {
                                                i++;
                                                ch++;
                                        }
                                        ch--;
                                }
                                eol=0;
                                ch++;
                        }
                        printf("\n");
                }
        }
}

/* Affiche les champs pour telnet */
void print_telnet(const u_char *payload, int len,int verbosite,int count)
{
        int i;
        int end_flag=0;
        const u_char *ch = payload;

        ch = payload;

        for(i = 0; i < len; i=i+3) {
                printf("           ");
                ch++;
                switch (*ch) {
                case 255: printf( "-- "); break;
                case 254: printf( "DONT "); break;
                case 253: printf( "DO "); break;
                case 252: printf( "WONT "); break;
                case 251: printf( "WILL "); break;
                case 250: printf( "SUBOPTION "); break;
                case 249: printf( "GA "); break;
                case 248: printf( "EL "); break;
                case 247: printf( "EC "); break;
                case 246: printf( "AYT "); break;
                case 245: printf( "AO "); break;
                case 244: printf( "IP "); break;
                case 243: printf( "BREAK "); break;
                case 242: printf( "DM "); break;
                case 241: printf( "NOP "); break;
                case 240: printf( "SUBOPTION-END \n"); end_flag=1; i=i-1; break;
                case 239: printf( "EOR "); break;
                case 238: printf( "ABORT "); break;
                case 237: printf( "SUSP "); break;
                case 236: printf( "xEOF "); break;
                default:
                        printf("UNKNOWN ");

                }
                ch++;

                if ( end_flag != 1 )
                {

                        switch (*ch) {
                        case 00: printf( "TRANSMIT-BINARY\n"); break;
                        case 1: printf( "ECHO\n"); break;
                        case 3: printf( "SUPPRESS-GO-AHEAD\n"); break;
                        case 5: printf( "STATUS\n"); break;
                        case 6: printf( "TIMING-MARK\n"); break;
                        case 10: printf( "NEGOCIATE-ABOUT-OUTPUT-CARRIAGE-RETURN-DISPOSITION\n");  break;
                        case 11: printf( "NEGOCAITE-ABOUT-OUTPUT-HORIZONTAL-TABSTOPS\n"); break;
                        case 12: printf( "NEGOCIATE-ABOUT-OUTPUT-HORIZONTAL-DISPOSITION\n"); break;
                        case 13: printf( "NEGOCIATE-ABOUT-FORMFEED-DISPOSITION\n"); break;
                        case 14: printf( "NEGOCIATE-ABOUT-OUTPUT-VERTICAL-TABSTOPS\n"); break;
                        case 15: printf( "NEGOCIATE-ABOUT-OUTPUT-VERTICAL-TAB-DISPOSITION\n"); break;
                        case 16: printf( "NEGOCIATE-ABOUT-OUTPUT-LINEFEED-DISPOSITION\n"); break;
                        case 17: printf( "EXTEND-ASCII\n"); break;
                        case 18: printf( "LOGOUT\n"); break;
                        case 19: printf( "BYTE-MACRO\n"); break;
                        case 20: printf( "DATA-ENTRY-TERMINAL\n"); break;
                        case 23: printf( "SEND-LOCATION\n");  break;
                        case 24: printf( "TERMINAL-TYPE\n"); break;
                        case 25: printf( "END-OF-RECORD\n"); break;
                        case 26: printf( "TUID\n"); break;
                        case 27: printf( "OUTMRK\n"); break;
                        case 28: printf( "TTYLOC\n"); break;
                        case 29: printf( "3270-REGIME\n"); break;
                        case 30: printf( "X.3-PAD\n"); break;
                        case 31: printf( "NEGOCIAtE-ABOUT-WINDOW-SIZE\n"); break;
                        case 32: printf( "TERMINAL-SPEED\n"); break;
                        case 33: printf( "TOGGLE-FLOW-CONTROL\n"); break;
                        case 34: printf( "LINEMODE\n"); break;
                        case 35: printf( "X-DISPLAY LOCATION\n"); break;
                        case 36: printf( "ENVIRON\n"); break;
                        case 37: printf( "AUTHENTIFICATION\n"); break;
                        case 38: printf( "ENCRYPT\n"); break;
                        case 39: printf( "NEW-ENVIRON\n"); break;
                        case 40: printf( "TN3270E\n"); break;
                        case 42: printf( "CHARSET\n"); break;
                        case 44: printf( "COM-PORT OPTION\n"); break;
                        case 47: printf( "KERMIT\n"); break;

                        default:
                                printf("UNKNOWN\n ");
                        }
                        ch++;
                        int j =0;

                        if ( *ch != 255 && i+3 != len)
                        {
                                printf("           Option data : \n           " );
                                while ( *ch != 255 && i < len)
                                {
                                        printf("%02x ", *ch);
                                        ch++;
                                        i++;
                                        j++;
                                        if ( j%16 == 0) printf("\n           ");
                                }
                                printf("\n");
                        }
                }
                end_flag=0;
        }
        printf("\n");
        return;

}

/* Affiche les champs pour ftp / http / imap / smtp / pop */
void print_ftp_http_imap_smtp_pop(const u_char *payload, int len,protocol_app p,int verbosite,int count)
{
        int i;
        int width = 150;
        int w=0;
        const u_char *ch = payload;

        if ( verbosite == 1 )
        {
                printf("# Packet number %d - ", count);
                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                switch (p) {
                case FTP:
                        printf("- Protocol : FTP - Length : %d - Info : ",paquet_length);
                        break;
                case HTTP:
                        printf("- Protocol : HTTP - Length : %d - Info : ",paquet_length);
                        break;
                case IMAP:
                        printf("- Protocol : IMAP - Length : %d - Info : ",paquet_length);
                        break;
                case SMTP:
                        printf("- Protocol : SMTP - Length : %d - Info : ",paquet_length);
                        break;
                case POP:
                        printf("- Protocol : POP - Length : %d - Info : ",paquet_length);
                        break;
                default:
                        printf("- Protocol : TCP - Length : %d - Info : ",paquet_length);
                        break;
                }

        }

        if ( verbosite == 3 )
        {
                ch = payload;
                printf("           ╔═ ");
                int cnt = 0;

                for(i = 0; i < len; i++) {
                        w++;
                        if (isprint(*ch))
                                printf("%c", *ch);
                        else
                        {
                                if (*ch ==  0xd)
                                        cnt++;
                                if (*ch ==  0xa)
                                        cnt++;
                                if ( cnt == 2)
                                {
                                        printf("\n           ╠═ ");
                                        cnt=0;
                                }
                        }
                        ch++;
                        if ( w == width )
                        {
                                w=0;
                                printf("\n           ╠═ ");
                        }
                }
                printf("\n           ╚═");
        }

        if ( verbosite == 1 )
        {
                ch = payload;
                int cnt = 0;
                int firstline = 0;

                for(i = 0; i < len; i++) {
                        w++;
                        if ( firstline == 0)
                        {
                                if ( w < width)
                                {
                                        if (isprint(*ch))
                                                printf("%c", *ch);
                                        else
                                        {
                                                if (*ch ==  0xd)
                                                        cnt++;

                                                if (*ch ==  0xa)
                                                        cnt++;
                                                if ( cnt == 2)
                                                {
                                                        firstline =1;
                                                        printf("\n");
                                                        cnt=0;
                                                }
                                        }
                                        ch++;

                                }
                        }

                }
        }
        return;
}



/* Traite et lance les fonctions d'affichage pour les protocoles applicatifs de tcp */
void print_tcppayload(const struct tcphdr *tcp,int tcp_len,int size_ip,int ip_tot_len,const u_char *packet,int verbosite,int count)
{
        const u_char *payload;
        int size_tcp = tcp->th_off*4;
        int size_payload;

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + size_tcp);
        size_payload = ip_tot_len - (size_ip + size_tcp);

        if ( tcp_len > 0 )
        {
                if ( ntohs(tcp->th_sport) == 25 || ntohs(tcp->th_dport) == 25 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : Simple Mail Transfer Protocol (SMTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload smtp(%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,SMTP,verbosite,count);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 143 || ntohs(tcp->th_dport) == 143 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : IMAP \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,IMAP,verbosite,count);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 110 || ntohs(tcp->th_dport) == 110 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : POP \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,POP,verbosite,count);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 23 || ntohs(tcp->th_dport) == 23 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : Telnet \n");
                        if ( verbosite ==1 )
                        {
                                printf("# Packet number %d - ", count);
                                printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                                printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                                printf("- Protocol : TELNET - Length : %d - Info : Telnet Data ..\n",paquet_length);
                        }
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                                if ( verbosite == 3 ) print_telnet(payload, size_payload,verbosite,count);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 80 || ntohs(tcp->th_dport) == 80 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : Hypertext Transfer Protocol (HTTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,HTTP,verbosite,count);
                        }
                }
                else if (  ntohs(tcp->th_sport) == 20 || ntohs(tcp->th_dport) == 21 || ntohs(tcp->th_sport) == 21 || ntohs(tcp->th_dport) == 20 ) {
                        if ( verbosite >= 2 ) printf("\n         Application layer : File Transfer Protocol (FTP) \n");
                        if (size_payload > 0) {
                                if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                                print_ftp_http_imap_smtp_pop(payload, size_payload,FTP,verbosite,count);
                        }
                }
                else {
                        if ( verbosite >= 2 ) printf("\n            Application layer : Unknown protocol\n");
                        print_ftp_http_imap_smtp_pop(payload, size_payload,-1,verbosite,count);
                }
        }
        else
        {
                if ( verbosite == 1 )
                {
                        printf("# Packet number %d - ", count);
                        printf("Source : %s - ",inet_ntoa(paquet_srcaddr));
                        printf("Destination : %s ",inet_ntoa(paquet_dstaddr));
                        printf("- Protocol : TCP - Length : %d - Info : %d -> %d [ ",paquet_length, ntohs(tcp->th_sport), ntohs(tcp->th_dport));

                        if (tcp->th_flags & TH_URG) {
                                printf("URG ");
                        }
                        if (tcp->th_flags & TH_ACK) {
                                printf("ACK ");
                        }
                        if (tcp->th_flags & TH_PUSH) {
                                printf("PUSH ");
                        }
                        if (tcp->th_flags & TH_RST) {
                                printf("RST ");
                        }
                        if (tcp->th_flags & TH_SYN) {
                                printf("SYN ");
                        }
                        if (tcp->th_flags & TH_FIN) {
                                printf("FIN ");
                        }
                        printf ("]\n");
                }
        }

}


/* Traite et lance les fonctions d'affichages pour les protocoles applicatifs d'udp */
void print_udppayload(const struct udphdr *udp,int size_ip,int ip_tot_len,const u_char *packet,int verbosite,int count)
{
        const u_char *payload;
        int size_payload;

        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + sizeof(udp));
        size_payload = ip_tot_len - (size_ip + sizeof(udp));

        if (  ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53 ) {

                if ( verbosite >= 2 ) printf("\n        Application layer : DNS \n");
                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                        print_dns(payload, size_payload,verbosite,count);

                }
        }
        else if (( ntohs(udp->uh_sport) == 67 && ntohs(udp->uh_dport) == 68 ) || ( ntohs(udp->uh_sport) == 68 && ntohs(udp->uh_dport) == 67 )) {

                if ( verbosite >= 2 ) printf("\n        Application layer: Bootstrap Protocol / DHCP \n");
                if (size_payload > 0) {
                        if ( verbosite == 3 ) printf("           Payload (%d bytes):\n", size_payload);
                        print_bootp(payload, size_payload,verbosite,count);
                }
        }
        else {
                if ( verbosite >= 3 ) printf("\n        Unknown Application layer (UDP)\n");

        }

}



/* Affiche les options tcp si existant */
void print_tcpoptions(const struct tcphdr *tcp, int size_ip,const u_char * packet,int verbosite,int count)
{
        int option_size;
        const u_char *payload;
        payload = (u_char *)(packet + sizeof(struct ether_header) + size_ip + 20);
        option_size = tcp->th_off*4 - 20;

        const u_char *ch = payload;
        int eol=0;

        ch = payload;
        if ( option_size > 0 )
        {
                printf("         ╚═ Options : (%d bytes),",option_size);

                for ( int i = 0; i < option_size; i++)
                {
                        switch (*ch) {
                        case TCPOPT_EOL: printf( " End of option list \n"); break;
                        case TCPOPT_NOP: printf( " No operation (NOP),"); eol=1; break;
                        case TCPOPT_MAXSEG: printf( " Maximum segment size,"); break;
                        case TCPOPT_WINDOW: printf( " Window Scale,"); break;
                        case TCPOPT_SACK_PERMITTED: printf( " SACK Permitted,"); break;
                        case TCPOPT_TIMESTAMP: printf(" Timestamps,"); break;
                        case TCPOLEN_TIMESTAMP: printf( " Timestamps,"); break;
                        case TCPOLEN_TSTAMP_APPA: printf( "   IP "); break;
                        default:
                                printf("UNKNOWN, ");
                        }

                        if ( eol == 0)
                        {
                                ch++;
                                int len = (u_int8_t)*ch;
                                len = len - 2;

                                ch++;
                                i++;
                                for ( int j = 0; j < len; j++)
                                {
                                        i++;
                                        ch++;
                                }
                                ch--;
                        }
                        eol=0;
                        ch++;
                }
                printf("\n");
        }


}
