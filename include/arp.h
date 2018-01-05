#ifndef PRINT_FUNCTIONS_H
#define PRINT_FUNCTIONS_H

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


#endif
