#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x \n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
void print_ip(const u_char* ip){
  printf("%d.%d.%d.%d \n",ip[0],ip[1],ip[2],ip[3]);
}

void print_port(const u_char* port){
  printf("%d \n",port[0]*256 + port[1]);
}

int print_icmp(const u_char* icmp){
    u_int16_t icmp1 = icmp[0] *256 + icmp[1];
    return icmp1;
}
void print_http(const u_char* http){
    if(http[0]==0x18){
        printf("TCP DATA:");
        printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",http[19],http[20],http[21],http[22],http[23],http[24],http[25],http[26],http[27],http[28]);
    }
}

void print_tcmp(const u_char* tcmp){
    if(tcmp[0]==0x11){
        printf("NO TCP \n",tcmp[0]);
    }
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
}

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE]; //ens33
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("=======================================================\n");
    printf("S-MAC: ");
    print_mac(&packet[0]);
    printf("D-MAC: ");
    int icmp = print_icmp(&packet[13]);
    if(icmp != 69){
        printf("NOT IPv4!!\n");
        continue;
    }
    print_mac(&packet[6]);
    printf("S-IP: ");
    print_ip(&packet[14+12]);
    printf("D-IP: ");
    print_ip(&packet[14+16]);
    print_tcmp(&packet[23]);
    printf("S-PORT: ");
    print_port(&packet[34]);
    printf("D-PORT: ");
    print_port(&packet[36]);
    print_http(&packet[47]);
    printf("%u bytes captured \n", header->caplen);
    printf("======================================================\n");
    printf("\n");
 }

  pcap_close(handle);
  return 0;
}
