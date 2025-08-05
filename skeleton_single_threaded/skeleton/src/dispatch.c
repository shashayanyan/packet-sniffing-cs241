#include "dispatch.h"

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "analysis.h"

#define MAX_IP_COUNT 100
#define MAX_THREADAS 2


pthread_mutex_t queueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER;


/*
void addToQueue(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose){
  pthread_mutex_lock(&queueMutex);
  enqueue(workQueue, (struct packetData){header, packet, verbose});
  pthread_cond_signal(&queueCond);
  pthread_mutex_unlock(&queueMutex);
}

// each packet will be analysed by a worker thread
void *workerThread(void *arg){
  while (1) {
    pthread_mutex_lock(&queueMutex);
    while(isempty(workQueue)){
      pthread_cond_wait(&queueCond, &queueMutex);
    }

    struct packetData packet = workQueue->head->packet;
    dequeue(workQueue);
    pthread_mutex_unlock(&queueMutex);


    struct analysisResponse * response = analyse(packet.header, packet.packet, packet.verbose);
    processResponse(response);
  }

}*/

/* threadpool initializer
void initializeThreadpool(){
  pthread_t threads[MAX_THREADAS];
  for (int i = 0; i < MAX_THREADAS; i++){
    pthread_create(&threads[i], NULL, workerThread, NULL);
  }
}*/

// keeping the IP addresses in a struct to check for uniqeness
struct IP_Address {
  char ip[16]; // considering only IPv4
};

//GLOBAL VARIABLES FOR REPORT
int ipArraySize = 1;
int synCount = 0;
int uniqueIPCount = 0;
struct IP_Address *sources = NULL;
int BBCCount = 0;
int GoogleCount = 0;
int ARPCount = 0;

// a function to check if ip is new or already exists
int isNewIP(const char *ip){
  for (int i = 0; i < uniqueIPCount; i++){
    if (strcmp(sources[i].ip, ip) == 0) {
      return 0;
    }
  }
  return 1;
}


// this function updates the record 
// but this does not sound right???
// dispatch just manages the worker threads
// it forwards every response to sniff and sniff should update and keep report!!!!
void processResponse(struct analysisResponse * response){
  if ( response->isSynAttack ) {
    synCount++;
    if (isNewIP(response->ip)){
      // it's a new unique IP let's add it
      if (uniqueIPCount < ipArraySize * MAX_IP_COUNT){
        strcpy(sources[uniqueIPCount].ip, response->ip);
        uniqueIPCount++;
      } else {
        //if array is full, realloc
      }
    }
  }

  if (response->isARPresponse){
    ARPCount++;
  }
  if (response->isBlackListedURL == 1){
    GoogleCount++;
  }
  else if (response->isBlackListedURL == 2){
    BBCCount++;
  }

  //free(response);
}

void finalReport(int signal){
  if (signal == SIGINT){
    printf("\nIntrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n", synCount, uniqueIPCount);
    printf("%d ARP responses (cache poisoning)\n", ARPCount);
    printf("%d URL Blacklist violations (%d google and %d bbc)\n", BBCCount+GoogleCount, GoogleCount, BBCCount);

    free(sources);
    //destroy_queue(workQueue);
    exit(EXIT_SUCCESS);
  }
}

void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  if (sources == NULL){
    sources = (struct IP_Address *)malloc(MAX_IP_COUNT * sizeof(struct IP_Address));
  }
  if (sources == NULL){
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  // setting up signal handler
  signal(SIGINT, finalReport);
  struct analysisResponse * response = analyse(header, packet, verbose);
  processResponse(response);
  free(response);
  response = NULL;
  //addToQueue(header, packet, verbose);


}

// *****************************************************
// functions for our queue
struct queue *create_queue(void) {
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head = NULL;
  q->tail = NULL;
  return (q);
}

int isempty(struct queue *q){
  return (q->head==NULL);
}


void enqueue(struct queue *q, struct packetData packet){
  struct node *new_node = (struct node *)malloc(sizeof(struct node));
  new_node->packet = packet;
  new_node->next=NULL;
  if (isempty(q)){
    q->head = new_node;
    q->tail = new_node;
  }
  else {
    q->tail->next = new_node;
    q->tail = new_node;
  }
}


void dequeue(struct queue *q){
  struct node *head_node;
  if (isempty(q)){
    printf("Error: attempt to dequeue from an empty queue\n");
  } else {
    head_node = q->head;
    q->head=q->head->next;
    if (q->head==NULL){
      q->tail=NULL;
    }
    free(head_node);
  }
}


void destroy_queue(struct queue *q){
  while (!isempty(q)){
    dequeue(q);
  }
  free(q);
}

// functions for our queue
// *****************************************************
