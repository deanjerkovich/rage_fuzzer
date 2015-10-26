#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <time.h>

#include "libmutant.h"
#include "rage.h"

int debug =0;
int send_delay=0;
int print_packets=0;
int modify_payload=1;
int packet_loop_counter=0;
int packet_loop_counter_max=10;
float FUZZ_RATIO = 0.05;

// global socket for reuse across send calls
int sockfd = NULL;

struct packetDescription
{
  char l3[4];
  char l4[4];
  int sport;
  int dport;
  char direction[4];
  char hexdata[10000]; // TODO fix these...
  char comment[128];
  struct packetDescription *next;
};

struct packetDescription *head = NULL;
struct packetDescription *current = NULL;

void usage()
{
  printf("Usage: rage [-d] -p <port> -t <target> -f <filename>\n");
  printf("        -f filename      file to read packet zoo from\n");
  printf("        -d               enable debug [excessive]\n");
  printf("        -l               print out all packets in file\n");
  printf("        -p portnum       specify target port for fuzzing\n");
  printf("        -t host          specify target host for fuzzing\n");
  printf("        -s milliseconds  specify a send delay \n");
  printf("        -b               don't fuzz, send original packets and exit \n");
  printf("        -r               provide a seed for srand (repeat a fuzz run)\n");
  printf("        -c               number of packets sent before forced reconnect\n");
  exit(1);
}


void addToList(char *line)
{
  struct packetDescription *newpkt
    = (struct packetDescription*)malloc(sizeof(struct packetDescription));
  char *token;
  int field=0;
  if (line[0]=='#')
  {
    if (debug) {printf("Bailing on line with comment\n");}
    return;
  }
  char *c;
  c = strchr(line,'\n');
  *c = '\0';
  if (debug) {printf("Full Line: ----%s----\n",line);}
  token = strtok(line,":");
  while (token !=NULL)
  {
    if (field==0) {
      strcpy(newpkt->l3,token);
      if (debug) {printf("l3: %s\n",token);}
    } else if (field==1) {
      strcpy(newpkt->l4,token);
      if (debug) {printf("l4: %s\n",token);}
    } else if (field==2) {
      newpkt->sport=atoi(token);
      if (debug) {printf("sport: %d\n",newpkt->sport);}
    } else if (field==3) {
      newpkt->dport=atoi(token);
      if (debug) {printf("dport: %d\n",newpkt->dport);}
    } else if (field==4) {
      strcpy(newpkt->direction,token);
      if (debug) {printf("direction: %s\n",token);}
    } else if (field==5) {
      strcpy(newpkt->hexdata,token);
      if (debug) {printf("hexdata: %s\n",token);}
    } else if (field==6) {
      strcpy(newpkt->comment,token);
      if (debug) {printf("comment: %s\n",token);}
    }
    token = strtok(NULL,":");
    field++;
  }
  if (head==NULL)
  {
    head = newpkt;
    newpkt->next=NULL;
  } else {
    newpkt->next = head;
    head = newpkt;
  }
  return;
}

// TODO FFS abomination, we can do better
int ascii_char_to_num(char c)
{
  switch (c)
  {
    case '0':
      return 0;
    case '1':
      return 1;
    case '2':
      return 2;
    case '3':
      return 3;
    case '4':
      return 4;
    case '5':
      return 5;
    case '6':
      return 6;
    case '7':
      return 7;
    case '8':
      return 8;
    case '9':
      return 9;
    case 'A':
      return 10;
    case 'a':
      return 10;
    case 'B':
      return 11;
    case 'b':
      return 11;
    case 'C':
      return 12;
    case 'c':
      return 12;
    case 'd':
      return 13;
    case 'D':
      return 13;
    case 'E':
      return 14;
    case 'e':
      return 14;
    case 'F':
      return 15;
    case 'f':
      return 15;
    default:
      printf("\nInvalid char in hex, exiting\n");
      printf("char: 0x%x\n",c);
      exit(1);
  }
}

void get_raw_from_ascii_hex(char *input, unsigned char *output)
{
  if (debug) {printf("debug: get_raw_from_ascii_hex\n");}
  int bytelen;
  int i;
  bytelen = strlen(input); 
  if (debug) {printf("debug: input len: %d\n",bytelen);}

  char *ptr;
  ptr = input;

  for (i=0;i<bytelen;i=i+2)
  {
    unsigned char result;
    unsigned char c1, c2;
    c1 = ascii_char_to_num(ptr[i])*16;
    c2 = ascii_char_to_num(ptr[i+1]);
    result = c1+c2;
    if (debug) {printf("[0x%02x] ",result);}
    output[i/2] = (unsigned char)result;
  }
  output[i/2]='\0';
}

void printByPortNo(int portNo)
{
  current = head;
  while (current!=NULL)
  {
    if (current->dport==portNo)
    {
      printf("PacketComment port %d: %s\n",portNo,current->comment);
    }
    current=current->next;
  }
  return;
}

void getPacketDescriptions(FILE *fp)
{
  char line[12000];
  void *r;
  int total_lines=0;
  r=fgets(line,12000,fp);
  while (r!=NULL)
  {
    addToList(line);
    r=fgets(line,12000,fp);
    total_lines++;
  }
  printf("[+] reading %d lines complete\n",total_lines);
  return;
}

void print_all_packets(int portnum)
{
  if (debug) {printf("Printing all packets with portnum %d\n",portnum);}
  current = head;
  while (current != NULL)
  {
    char sport_text[8];
    char dport_text[8];
    char direction[4];
    char outtext[128];
    int outlen=0;
    int i;
    if (portnum!=0 && portnum!=current->dport)
    {
      current=current->next;
      continue;
    }
    if (current->sport==0)
    {
      strcpy(sport_text,"*");
    }
    else
    {
      sprintf(sport_text,"%d",current->sport);
    }
    if (current->dport==0)
    {
      strcpy(dport_text,"*");
    }
    else
    {
      sprintf(dport_text,"%d",current->dport);
    }
    if (strcmp(current->direction,"CS"))
    {
      strcpy(direction,"<--");
    } else
    {
      strcpy(direction,"-->");
    }
    sprintf(outtext,"%s/%s [ %s %s %s ]",current->l3,current->l4,sport_text,direction,dport_text);
    outlen = strlen(outtext);
    for (i=24;i>outlen;i--) strcat(outtext," ");
    strcat(outtext,current->comment);
    printf("%s\n",outtext);
    current=current->next;
  }
  return;
}

char * ascii_to_binary(char *input)
{
  if (debug) {printf("debug: called into ascii_to_binary with %d bytes\n",strlen(input));}
  if (debug) {printf("debug: ascii_to_binary in: %s\n",input);}
  unsigned char *output;
  output = malloc((strlen(input)/2)+1);
  get_raw_from_ascii_hex(input,output);
  return output;
}


void send_packet(unsigned char *databuf,int portnum,char *target_host, int data_buffer_len)
{
  struct sockaddr_in dest;
  int sendval;

  bzero((char *)&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(portnum);

  if (inet_aton(target_host, (struct in_addr *)&dest.sin_addr.s_addr)==0)
  {
    printf("Error with address\n");
    exit(errno);
  }
  if (debug) {printf("Addr: %s\n",target_host);}
  if (debug) {printf("Send()ing %d bytes thru sock: 0x%x\n",data_buffer_len,sockfd); }
  sendval = send(sockfd, databuf, data_buffer_len, MSG_NOSIGNAL);
  if (sendval == -1)
  {
    if (debug) {printf("send() failed: %d, reconnecting\n",sendval);}
    if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) !=0)
    {
      if (debug) {printf("\n\nConnect() error, try new socket");}
      init_sock();
      if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) !=0)
      {
        printf("\n\nConnect() error, exiting");
        exit(errno);
      }
    }
    sendval = send(sockfd, databuf, data_buffer_len, 0);
    if (debug) {printf("send() retval after reconnect: %d\n",sendval);}
  } 
  if (debug) {printf("appears to have send() successfully\n");}
  packet_loop_counter++;
  if (packet_loop_counter>packet_loop_counter_max)
  {
    packet_loop_counter=0;
    close(sockfd);
    init_sock();
  }
  return;
}

void init_sock()
{
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (sockfd <0)
    {
      printf("Socket error\n");
      exit(errno);
    }
}

void begin_fuzzer(int portnum, char *target_host)
{
  char port_print[8];
  unsigned char *data_buffer;
  unsigned int data_buffer_len;
  int i=0;
  int outbuflen=0;
  char outbuffer[64];
  int packets_sent=0;
  if (portnum==0)
  {
    strcpy(port_print,"ALL");
  } else {
    sprintf(port_print,"%d",portnum);
  }
  init_sock();
  printf("[+] beginning fuzz run against: %s:%s\n\n",target_host,port_print);
  while (1)
  {
    current = head;
    while (current!=NULL)
    {
      if (current->dport!=portnum)
      {
        current=current->next;
        continue;
      }
      data_buffer = ascii_to_binary(current->hexdata);
      data_buffer_len = (strlen(current->hexdata)/2);
      if (packets_sent%100==0)
      {
        for(;outbuflen>0;outbuflen--)
        {
          printf("\b");
        }
        sprintf(outbuffer,"Sent %d packets",packets_sent);
        outbuflen = strlen(outbuffer);
        printf("%s",outbuffer);
        fflush(stdout);
      }
      if (modify_payload)
      {
        data_buffer = do_fuzz_random(data_buffer,data_buffer_len);
      }
      if (debug) {printf("Attempting to send data\n");}
      usleep(send_delay*1000);
      send_packet(data_buffer,portnum,target_host,data_buffer_len);
      packets_sent++;
      free(data_buffer);
      current=current->next;
    }
    if (modify_payload==0)
    {
      printf("\n\nSent all packets unmodified, exiting\n\n");
      exit(0);
    }
  }
}

void save_seed(int seed, char *fullCmdLine)
{
  time_t sec;
  char *time_str;
  sec = time(NULL);
  time_str = ctime(&sec);
  time_str[strlen(time_str)-1] = '\0';
  FILE *seedFile = fopen("seeds.log","a");
  fprintf(seedFile,"%s, cmd:%s seed was: %d\n",time_str,fullCmdLine,seed);
  fclose(seedFile);
}

int main(int argc, char **argv)
{
  FILE *fp;
  printf("RAGE AGAINST THE NETWORK\n");
  char *fileName = NULL;
  char *target_host = NULL;
  unsigned int supplied_seed =0;
  int portnum=0;
  int c;
  char *fullCmdLine[128];
  strcpy(fullCmdLine,argv[0]);
  int i;
  for (i=1;i<argc;i++)
  {
    strcat(fullCmdLine," ");
    strcat(fullCmdLine,argv[i]);
  }
	while ((c = getopt(argc, argv, "ldbf:p:t:s:r:c:")) != -1)
	{
    switch (c)
    {
      case 'f':
        fileName = optarg;
        break;
      case 'd':
        debug=1;
        break;
      case 'l':
        print_packets=1;
        break;
      case 'p':
        portnum = atoi(optarg);
        if (debug) {printf("debug: port %d parsed\n",portnum);}
        break;
      case 't':
        target_host = optarg;
        break;
      case 'b':
        modify_payload = 0;
        break;
      case 's':
        send_delay = atoi(optarg);
        break;
      case 'r':
        supplied_seed=atoi(optarg);
        break;
      case 'c':
        packet_loop_counter_max = atoi(optarg);
        break;
      default:
        abort();
    }
  }
  if (fileName==NULL)
  {
    usage();
  }
  if (supplied_seed)
  {
    printf("[+] supplied seed: %d\n",supplied_seed);
    save_seed(supplied_seed,fullCmdLine);
    srand(supplied_seed);
  } else
  {
    unsigned int seed = time(NULL);
    printf("[+] seed: %d\n", seed);
    save_seed(seed,fullCmdLine);
    srand(seed);
  }
  printf("[+] opening: %s\n", fileName);
  fp = fopen(fileName,"r");
  if (fp==NULL)
  {
    printf("Error: Can't open %s, exiting\n",fileName);
    exit(1);
  }
  if (portnum==0)
  {
    printf("[+] Port chosen: ALL\n",portnum);
  } else
  {
    printf("[+] Port chosen: %d\n",portnum);
  }
  getPacketDescriptions(fp);
  fclose(fp);
  if (print_packets)
  {
    print_all_packets(portnum);
  }
  if (target_host!=NULL && portnum!=0)
  {
    begin_fuzzer(portnum,target_host);
  }
  return 0;
}
