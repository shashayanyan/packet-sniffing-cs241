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
//extern struct queue *workQueue;
#endif
