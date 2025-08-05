#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>

#include "dispatch.h"

pcap_t *pcap_handle;
void handler(int sig){
  if (pcap_handle != NULL){
    pcap_breakloop(pcap_handle);
  }
}

void packet_handler_function(unsigned char *data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet){
  if (*(int *)data){
    // verbose flag = 1
    dump(packet, pkthdr->len);
  }
  // initiating dispatch
  // dispatch shoud give back the report on the packet and we then update
  // the intrusion records
  dispatch(pkthdr, packet, *(int *)data);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // setting up signal handler
  struct sigaction sa;
  sa.sa_handler = handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGINT, &sa, NULL) == -1){
    perror("sigaction");
    exit(EXIT_FAILURE);
  }

  
  //struct pcap_pkthdr header;
  //const unsigned char *packet;

  // Create the work queue
  //workQueue = create_queue();

  // initialize our threadpool
  //initializeThreadpool();

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().

  pcap_loop(pcap_handle, 0, packet_handler_function, (unsigned char *)&verbose);
  pcap_close(pcap_handle);


}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  // Decode IP Header
  struct ip *ip_header = (struct ip *)(data + ETH_HLEN);
  printf("\n === PACKET %ld IP HEADER ===", pcount);
  printf("\nSource IP: %s", inet_ntoa(ip_header->ip_src));
  printf("\nDestination IP: %s", inet_ntoa(ip_header->ip_dst));
  printf("\nProtocol: %d", ip_header->ip_p);

  // Convert network byte order to host byte order
  unsigned short ethernet_type = ntohs(eth_header->ether_type);

  // Decode TCP Header if the protocol is TCP
  if (ethernet_type == ETHERTYPE_IP && ip_header->ip_p == IPPROTO_TCP) {
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ETH_HLEN + ip_header->ip_hl * 4);
    printf("\n === PACKET %ld TCP HEADER ===", pcount);
    printf("\nSource Port: %hu", ntohs(tcp_header->th_sport));
    printf("\nDestination Port: %hu", ntohs(tcp_header->th_dport));
    printf("\nFlags: %x", ntohs(tcp_header->th_flags));
    printf("\nSYN:%d", tcp_header->syn);
  }

  pcount++;
}
