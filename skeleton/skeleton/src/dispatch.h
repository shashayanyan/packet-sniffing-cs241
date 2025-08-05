#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "analysis.h"

struct packetData{ // data structure for packet data
    const struct pcap_pkthdr *header;
    const unsigned char *packet;
    int verbose;
};

struct node { // data structure for each node
    struct packetData packet;
    struct node *next;
};

struct queue{ // data structure for queue
    struct node *head;
    struct node *tail;
};

// keeping the IP addresses in a struct to check for uniqeness
struct IP_node {
  char ip[16]; // considering only IPv4
  struct IP_node* next;
};

int is_new_ip(const char *ip, struct IP_node* head);
struct IP_node* createIPNode(const char* ip);
void insertIP(struct IP_node** head, const char* ip);
void free_sources(struct IP_node* head);

struct queue *create_queue(void);
int isempty(struct queue *q);
void enqueue(struct queue *q, struct packetData packet);
void dequeue(struct queue *q);
void destroy_queue(struct queue *q);


void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void processResponse(struct analysisResponse * response);
int isNewIP(const char *ip);
void initializeThreadpool();
//our work queue
extern struct queue *workQueue;

#endif
