#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_IP_COUNT 100
#define HTTP_PORT 80

struct IPAddress {
  char ipad[16]; // as the specification asks to only consider IPv4
};

struct BlacklistedURL {
  char url[50];
};

struct BlacklistedURL blacklistedURLs[] = {
  {"www.google.co.uk"},
  {"www.bbc.co.uk"}
};

int isURLBlacklisted(const char *url){
  for (int i = 0; i < 2; i++){
    if (strstr(url, blacklistedURLs[i].url) != NULL){

      return i+1; // black listed
    }
  }
  return 0; // not black listed
}

// probably should return some info to dispatch, as analyse anlyses one packet per iteration 
// but we will see into that later after making sure we detect SYN
// attacks correctly, proceedidng with global variables relative to the scope of
// analysis.c for now


struct analysisResponse * analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
  struct analysisResponse * response = (struct analysisResponse *) malloc(sizeof(struct analysisResponse));
  response->isSynAttack = 0;
  response->isBlackListedURL = 0;
  response->isARPresponse = 0;


  // packet structure to look for for syn attacks ehternet + ip + tcp
  struct ether_header *eth_header = (struct ether_header *)packet;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {

    const unsigned char *ip_packet = packet + sizeof(struct ether_header);
    struct ip *ip_header = (struct ip *)ip_packet;

    if (ip_header->ip_p == IPPROTO_TCP) {

      const unsigned char *tcp_packet = ip_packet + (ip_header->ip_hl << 2);
      struct tcphdr *tcp_header = (struct tcphdr *)tcp_packet;

      // now checking for syn
      if (tcp_header->syn && !tcp_header->ack){
        response->isSynAttack = 1;

        // getting the IP address of the source
        const char *sourceIP = inet_ntoa(ip_header->ip_src);
        strcpy(response->ip, sourceIP);

      }

      if (ntohs(tcp_header->th_dport) == HTTP_PORT){
        const unsigned char *http_payload = tcp_packet + (tcp_header->th_off << 2);
        int isBlacklisted = isURLBlacklisted((const char *)http_payload);
        if (isBlacklisted){
          response->isBlackListedURL = isBlacklisted;
          const char *sourceIP = inet_ntoa(ip_header->ip_src);
          const char *destIP = inet_ntoa(ip_header->ip_dst);
          printf("==============================\n");
          printf("Blacklisted URL violation detected\n");
          printf("Source IP address: %s\n", sourceIP);
          char *site = isBlacklisted == 1 ? "google" : "bbc";
          printf("Destination IP address: %s (%s)\n", destIP, site);
          printf("==============================\n");

        }

      }

    }
  }

  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    const unsigned char *arp_packet = packet+sizeof(struct ether_header);
    struct ether_arp *arp_header = (struct ether_arp *)arp_packet;

    if (ntohs(arp_header->arp_op) == ARPOP_REPLY){
      response->isARPresponse = 1;
    }
  }



  return response;

}
