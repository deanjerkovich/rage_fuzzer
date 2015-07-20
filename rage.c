#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <time.h>

int debug=0;
int send_delay=0;
int print_packets=0;
int modify_payload=1;
float FUZZ_RATIO = 0.05;

struct packetDescription
{
  char l3[4];
  char l4[4];
  int sport;
  int dport;
  char direction[4];
  char hexdata[10000];
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

// abomination, we can do better
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
      printf("\n++++++++++++++++++++++");
      printf("\nInvalid codes, exiting\n");
      printf("++++++++++++++++++++++\n\n");
      exit(1);
  }
}

void get_raw_from_ascii_hex(char *input, unsigned char *output)
{
  if (debug) {printf("debug: get_raw_from_ascii_hex\n");}
  int bytelen;
  int i;
  bytelen = strlen(input);

  char *ptr;
  ptr = input;

  for (i=0;i<bytelen;i=i+2)
  {
    unsigned char result;
    unsigned char c1, c2;
    c1 = ascii_char_to_num(ptr[i])*16;
    c2 = ascii_char_to_num(ptr[i+1]);
    result = c1+c2;
    //printf("[0x%02x] ",result);
    output[i/2] = (unsigned char)result;
  }
  output[i]='\0';
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
  //unsigned char *output;
  //output = malloc(4096*sizeof(char));
  if (debug) {printf("debug: called into ascii_to_binary with %d bytes\n",strlen(input));}
  if (debug) {printf("debug: ascii_to_binary in: %s\n",input);}
  unsigned char *output;
  output = malloc((strlen(input)/2)+1);
  get_raw_from_ascii_hex(input,output);
  return output;
}

unsigned char* do_fuzz(unsigned char *databuf, int data_buffer_len) //todo don't permanently wreck all the data! or are we?
{
  int bytes_to_fuzz, i,b;
  unsigned char c;
  bytes_to_fuzz = (data_buffer_len * FUZZ_RATIO);
  if (debug) printf("buflen: %d, bytes_to_fuzz: %d\n", data_buffer_len, bytes_to_fuzz);
  for (i=0;i<bytes_to_fuzz;i++)
  {
    b = rand() % data_buffer_len;
    c = rand() % 256;
    databuf[b] = c;
    if (debug) {printf("Changing byte %d to 0x%x\n",b,c);}
  }
  return databuf;
}

send_packet(unsigned char *databuf,int portnum,char *target_host, int data_buffer_len)
{
  int sockfd;
  struct sockaddr_in dest;

  sockfd = socket(AF_INET,SOCK_STREAM,0);
  if (sockfd <0)
  {
    printf("Socket error\n");
    exit(errno);
  }

  bzero((char *)&dest, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(portnum);

  //if (inet_addr(target_host, &dest.sin_addr.s_addr)==0)
  if (inet_aton(target_host, &dest.sin_addr.s_addr)==0)
  {
    printf("Error with address\n");
    exit(errno);
  }
  if (debug) {printf("Addr: %s\n",target_host);}

  if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) !=0)
  {
    printf("Connect() error\n");
    exit(errno);
  }

  if (debug) {printf("Sending %d bytes \n",data_buffer_len); }
  send(sockfd, databuf, data_buffer_len, 0);
  //write(sockfd, databuf, data_buffer_len);
  close(sockfd);
  return;
}

void begin_fuzzer(int portnum, char *target_host)
{
  char port_print[8];
  unsigned char *data_buffer;
  int data_buffer_len;
  int i=0;
  if (portnum==0)
  {
    strcpy(port_print,"ALL");
  } else {
    sprintf(port_print,"%d",portnum);
  }
  srand(time(NULL));
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
      printf(".");
      fflush(stdout);
      if (modify_payload)
      {
        data_buffer = do_fuzz(data_buffer,data_buffer_len);
      }
      if (debug) {printf("Attempting to send data\n");}
      usleep(send_delay*1000);
      send_packet(data_buffer,portnum,target_host,data_buffer_len);
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

int main(int argc, char **argv)
{
  FILE *fp;
  printf("---rage against the network---\n");
  char *fileName = NULL;
  char *target_host = NULL;
  int portnum=0;
  int c;
	while ((c = getopt(argc, argv, "ldbf:p:t:s:")) != -1)
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
      default:
        abort();
    }
  }
  if (fileName==NULL)
  {
    usage();
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
  //printByPortNo(445);
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
