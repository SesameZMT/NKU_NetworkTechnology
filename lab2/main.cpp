#include<Winsock2.h>
#include<iostream>
#include<pcap.h>
#include<stdio.h>
#include<time.h>
#include<string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

using namespace std;

typedef struct IPHeader_t {		//IP首部
	BYTE Ver_HLen;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;//服务类型
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
}IPHeader_t;

void pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void IP_Packet_Handle(const struct pcap_pkthdr* packet_header, const u_char* packet_content);

int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	int num = 0;//接口数量
	char errbuf[PCAP_ERRBUF_SIZE];

	/*获取本地机器设备列表*/
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL/*auth is not needed*/, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex:%s\n", errbuf);
		exit(1);
	}
	/*打印列表*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", num++, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (num == 0)
	{
		printf("\n No interfaces found!\n");
		exit(1);
	}

	int n;
	cout << "请输入要打开的网络接口号" << "（0~" << num-1 << "）：" << endl;
	cin >> n;
	num = 0;

	for (d = alldevs; num < (n);num++)
	{
		d = d->next;
	}

	pcap_t * adhandle = pcap_open(
		d->name, // name of the device
		65536, // portion of the packet to capture
		// 65536 guarantees that the whole packet
		// will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS | // promiscuous mode
		PCAP_OPENFLAG_NOCAPTURE_LOCAL | PCAP_OPENFLAG_MAX_RESPONSIVENESS,
		1000, // read timeout
		NULL,
		errbuf); // error buffer
	if (adhandle == NULL)
	{
		cout << "产生错误，无法打开设备" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		cout << "监听：" << d->description << endl;
		pcap_freealldevs(alldevs);

	}

	int read_count;
	cout << "请输入你要捕获的数据包的个数：" << endl;
	cin >> read_count;
	pcap_loop(adhandle, read_count, (pcap_handler)pcap_callback, NULL);
	pcap_close(adhandle);

	return 0;
}

void pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) //packet_content表示的捕获到的数据包的内容
{
	const u_char* ethernet_protocol;		//以太网协议
	u_short ethernet_type;		//以太网类型
	//获取以太网数据内容
	ethernet_protocol = packet_content;
	ethernet_type = (ethernet_protocol[12] << 8) | ethernet_protocol[13];
	printf("Mac源地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		(ethernet_protocol[6]),
		(ethernet_protocol[7]),
		(ethernet_protocol[8]),
		(ethernet_protocol[9]),
		(ethernet_protocol[10]),
		(ethernet_protocol[11])
	);
	printf("Mac目的地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		(ethernet_protocol[0]),
		(ethernet_protocol[1]),
		(ethernet_protocol[2]),
		(ethernet_protocol[3]),
		(ethernet_protocol[4]),
		(ethernet_protocol[5])
	);
	printf("以太网类型为 :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("网络层是：IPv4协议\n");
		break;
	case 0x0806:
		printf("网络层是：ARP协议\n");
		break;
	case 0x8035:
		printf("网络层是：RARP协议\n");
		break;
	default:
		printf("网络层协议未知\n");
		break;
	}
	if (ethernet_type == 0x0800)
	{
		IP_Packet_Handle(packet_header, packet_content);
	}
}

void IP_Packet_Handle(const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
	IPHeader_t* IPHeader;
	IPHeader = (IPHeader_t*)(packet_content + 14);//IP包的内容在原有物理帧后14字节开始
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	printf("版本：%d\n", IPHeader->Ver_HLen >> 4);
	printf("IP协议首部长度：%d Bytes\n", (IPHeader->Ver_HLen & 0x0f) * 4);
	printf("服务类型：%d\n", IPHeader->TOS);
	printf("总长度：%d\n", ntohs(IPHeader->TotalLen));
	printf("标识：0x%.4x (%i)\n", ntohs(IPHeader->ID));
	printf("标志：%d\n", ntohs(IPHeader->Flag_Segment));
	printf("片偏移：%d\n", (IPHeader->Flag_Segment) & 0x8000 >> 15);
	printf("生存时间：%d\n", IPHeader->TTL);
	printf("协议号：%d\n", IPHeader->Protocol);
	printf("协议种类：");
	switch (IPHeader->Protocol)
	{
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UDP\n");
		break;
	default:
		break;
	}
	printf("首部检验和：0x%.4x\n", ntohs(IPHeader->Checksum));
	printf("源地址：%s\n", sourceIP);
	printf("目的地址：%s\n", destIP);
	cout << "--------------------------------------------------------------------------------" << endl;
}