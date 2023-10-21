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

typedef struct IPHeader_t {		//IP�ײ�
	BYTE Ver_HLen;//IPЭ��汾��IP�ײ����ȣ���4λΪ�汾����4λΪ�ײ��ĳ���
	BYTE TOS;//��������
	WORD TotalLen;//�ܳ���
	WORD ID;//��ʶ
	WORD Flag_Segment;//��־ Ƭƫ��
	BYTE TTL;//��������
	BYTE Protocol;//Э��
	WORD Checksum;//ͷ��У���
	u_int SrcIP;//ԴIP
	u_int DstIP;//Ŀ��IP
}IPHeader_t;

void pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void IP_Packet_Handle(const struct pcap_pkthdr* packet_header, const u_char* packet_content);

int main()
{
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	int num = 0;//�ӿ�����
	char errbuf[PCAP_ERRBUF_SIZE];

	/*��ȡ���ػ����豸�б�*/
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL/*auth is not needed*/, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex:%s\n", errbuf);
		exit(1);
	}
	/*��ӡ�б�*/
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
	cout << "������Ҫ�򿪵�����ӿں�" << "��0~" << num-1 << "����" << endl;
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
		cout << "���������޷����豸" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		cout << "������" << d->description << endl;
		pcap_freealldevs(alldevs);

	}

	int read_count;
	cout << "��������Ҫ��������ݰ��ĸ�����" << endl;
	cin >> read_count;
	pcap_loop(adhandle, read_count, (pcap_handler)pcap_callback, NULL);
	pcap_close(adhandle);

	return 0;
}

void pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) //packet_content��ʾ�Ĳ��񵽵����ݰ�������
{
	const u_char* ethernet_protocol;		//��̫��Э��
	u_short ethernet_type;		//��̫������
	//��ȡ��̫����������
	ethernet_protocol = packet_content;
	ethernet_type = (ethernet_protocol[12] << 8) | ethernet_protocol[13];
	printf("MacԴ��ַ��\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		(ethernet_protocol[6]),
		(ethernet_protocol[7]),
		(ethernet_protocol[8]),
		(ethernet_protocol[9]),
		(ethernet_protocol[10]),
		(ethernet_protocol[11])
	);
	printf("MacĿ�ĵ�ַ��\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		(ethernet_protocol[0]),
		(ethernet_protocol[1]),
		(ethernet_protocol[2]),
		(ethernet_protocol[3]),
		(ethernet_protocol[4]),
		(ethernet_protocol[5])
	);
	printf("��̫������Ϊ :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("������ǣ�IPv4Э��\n");
		break;
	case 0x0806:
		printf("������ǣ�ARPЭ��\n");
		break;
	case 0x8035:
		printf("������ǣ�RARPЭ��\n");
		break;
	default:
		printf("�����Э��δ֪\n");
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
	IPHeader = (IPHeader_t*)(packet_content + 14);//IP����������ԭ������֡��14�ֽڿ�ʼ
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	printf("�汾��%d\n", IPHeader->Ver_HLen >> 4);
	printf("IPЭ���ײ����ȣ�%d Bytes\n", (IPHeader->Ver_HLen & 0x0f) * 4);
	printf("�������ͣ�%d\n", IPHeader->TOS);
	printf("�ܳ��ȣ�%d\n", ntohs(IPHeader->TotalLen));
	printf("��ʶ��0x%.4x (%i)\n", ntohs(IPHeader->ID));
	printf("��־��%d\n", ntohs(IPHeader->Flag_Segment));
	printf("Ƭƫ�ƣ�%d\n", (IPHeader->Flag_Segment) & 0x8000 >> 15);
	printf("����ʱ�䣺%d\n", IPHeader->TTL);
	printf("Э��ţ�%d\n", IPHeader->Protocol);
	printf("Э�����ࣺ");
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
	printf("�ײ�����ͣ�0x%.4x\n", ntohs(IPHeader->Checksum));
	printf("Դ��ַ��%s\n", sourceIP);
	printf("Ŀ�ĵ�ַ��%s\n", destIP);
	cout << "--------------------------------------------------------------------------------" << endl;
}