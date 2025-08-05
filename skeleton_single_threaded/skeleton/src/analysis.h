#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>


struct analysisResponse {
    int isSynAttack; // 0: no, 1: yes
    char ip[16]; // only considering IPv4
    int isBlackListedURL; // 0: no, 1: yes GOOGLE 2: yes BBC
    int isARPresponse; // 0: no, 1: yes
};


struct analysisResponse * analyse(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose);

#endif
