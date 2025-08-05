#include "dispatch.h"

#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "analysis.h"

#define MAX_THREADS 2

//our variables for threadpool
struct queue *workQueue;
pthread_mutex_t queueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queueCond = PTHREAD_COND_INITIALIZER;
pthread_t threads[MAX_THREADS];
int tasks_by_thread[MAX_THREADS];

//GLOBAL VARIABLES FOR REPORT
int synCount = 0;
int uniqueIPCount = 0;
struct IP_node* sources = NULL;
int BBCCount = 0;
int GoogleCount = 0;
int ARPCount = 0;

void addToQueue(const struct pcap_pkthdr *header, const unsigned char *packet, int verbose){
  pthread_mutex_lock(&queueMutex);
  enqueue(workQueue, (struct packetData){header, packet, verbose});
  pthread_cond_signal(&queueCond);
  pthread_mutex_unlock(&queueMutex);
}

// each packet will be analysed by a worker thread
void *workerThread(void *arg){
  int thread_num = *((int*)arg);
  free(arg);
  arg=NULL;
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
    free(response);

    tasks_by_thread[thread_num]++;
    response = NULL;
  }

}

/* threadpool initializer*/
void initializeThreadpool(){

  for (int i = 0; i < MAX_THREADS; i++){
    int* thread_num = malloc(sizeof(int));
    *thread_num = i;
    pthread_create(&threads[i], NULL, workerThread, (void *)thread_num);
    tasks_by_thread[i] = 0;
  }
}


// this function updates the record 
void processResponse(struct analysisResponse * response){
  if ( response->isSynAttack ) {
    synCount++;

    if (is_new_ip(response->ip, sources)){
      insertIP(&sources, response->ip);
      uniqueIPCount++;
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

}


void cleanupThreadpool(){
  for (int i = 0; i < MAX_THREADS; i++){
    pthread_cancel(threads[i]);
    pthread_join(threads[i], NULL);
  }
}

void finalReport(int signal){
  if (signal == SIGINT){
    for (int i = 0; i < MAX_THREADS; i++){
      pthread_detach(threads[i]);
    }    
    printf("\nIntrusion Detection Report:\n");
    printf("%d SYN packets detected from %d different IPs (syn attack)\n", synCount, uniqueIPCount);
    printf("%d ARP responses (cache poisoning)\n", ARPCount);
    printf("%d URL Blacklist violations (%d google and %d bbc)\n", BBCCount+GoogleCount, GoogleCount, BBCCount);

    for (int i = 0; i < MAX_THREADS; i++){
      //printf("thread index %d did %d tasks\n", i, tasks_by_thread[i]);
    }
    free_sources(sources);
    sources = NULL;
    destroy_queue(workQueue);
    workQueue = NULL;

    cleanupThreadpool();

    exit(EXIT_SUCCESS);
  }
}


void dispatch(const struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  // setting up signal handler
  signal(SIGINT, finalReport);

  addToQueue(header, packet, verbose);
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

// functions for our linked list containing unique IPs

int is_new_ip(const char *ip, struct IP_node* head){
  while (head != NULL){
    if (strcmp(head->ip, ip) == 0){
      return 0;
    }
    head = head->next;
  }
  return 1;
}

struct IP_node* createIPNode(const char* ip){
  struct IP_node* newNode = (struct IP_node*)malloc(sizeof(struct IP_node));
  strcpy(newNode->ip, ip);
  newNode->next = NULL;

  return newNode;
}

void insertIP(struct IP_node** head, const char* ip){
  struct IP_node* newNode = createIPNode(ip);
  newNode->next = *head;
  *head = newNode;
}

void free_sources(struct IP_node* head){
  while (head != NULL) {
    struct IP_node* tmp = head;
    head = head->next;
    free(tmp);
  }
}
// *****************************************************