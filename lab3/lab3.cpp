#include <Winsock2.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//��ʾ���ӵ�ʱ����ws2_32.lib
#pragma warning( disable : 4996 )//Ҫʹ�þɺ���
#define _WINSOCK_DEPRECATED_NO_WARNINGS
using namespace std;
void SetColor(int fore = 7, int back = 0) {
	unsigned char m_color = fore;
	m_color += (back << 4);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), m_color);
	return;
}
void printMAC(BYTE MAC[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (i < 5)
		{
			SetColor(14,0);
			printf("%02x:", MAC[i]);
		}
			
		else
		{
			SetColor(14, 0);
			printf("%02x:", MAC[i]);
		}
	}

};
void printIP(DWORD IP)
{
	BYTE* p = (BYTE*)&IP;
	for (int i = 0; i < 3; i++)
	{
		SetColor(14, 0);
		cout << dec << (int)*p << ".";
		p++;
	}
	SetColor(14, 0);
	cout << dec << (int)*p;
};
#pragma pack(1)
struct FrameHeader_t //֡�ײ�
{
	BYTE DesMAC[6];  //Ŀ�ĵ�ַ
	BYTE SrcMAC[6];  //Դ��ַ
	WORD FrameType;  //֡����
};

struct ARPFrame_t               //ARP֡
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()
int main()
{
	pcap_if_t* alldevs;//ָ���豸�б��ײ���ָ��
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//������Ϣ������
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;

	int index = 0;
	DWORD SendIP;
	DWORD RevIP;

	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		SetColor(12, 0);
		cout << "��ȡ����ӿ�ʱ��������:" << errbuf << endl;
		return 0;
	}
	//��ʾ�ӿ��б�
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		SetColor(7,0);
		cout << "����" << index + 1 << "\t" << ptr->name << endl;
		cout << "������Ϣ��" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{

			if (a->addr->sa_family == AF_INET)
			{
				SetColor(14, 0);
				cout << "  IP��ַ��" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  �������룺" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;

			}
		}

		index++;
	}

	int num;
	SetColor(13, 0);
	cout << "��ѡҪ�򿪵������ţ�";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//������
	if (pcap_handle == NULL)
	{
		SetColor(12, 0);
		cout << "������ʱ��������" << errbuf << endl;
		return 0;
	}
	else
	{
		SetColor(10,0);
		cout << "�ɹ��򿪸�����" << endl;
	}

	//��װ����
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
		ARPFrame.RecvHa[i] = 0;//��ARPFrame.RecvHa����Ϊ0��ʾĿ�ĵ�ַδ֪
		ARPFrame.SendHa[i] = 0x66;//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4; // Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//ԴIP��ַ����Ϊ�����IP��ַ 112.112.112.112.112.112

	//����ѡ���������IP����Ϊ�����IP��ַ
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	SetColor(10,0);
	cout << "ARP�����ͳɹ�" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			SetColor(12, 0);
			cout << "  �������ݰ�ʱ��������" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				SetColor(12, 0);
				cout << "  û�в������ݱ�" << endl;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//�ж��ǲ���һ��ʼ���İ�
				{
					SetColor(14,0);
					cout << " IP��";
					printIP(IPPacket->SendIP);
					cout << endl;
					cout << " MAC��";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
			}
		}
	}

	//�����緢�����ݰ�
	SetColor(13,0);
	cout << "\n" << endl;
	cout << "�����緢��һ�����ݰ�" << endl;
	cout << "����IP��ַ:";
	char str[32];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//������IP��ֵ�����ݱ���ԴIP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		SetColor(12, 0);
		cout << "ARP������ʧ��" << endl;
	}
	else
	{
		SetColor(10,0);
		cout << "ARP�����ͳɹ�" << endl;

		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				SetColor(12, 0);
				cout << "  �������ݰ�ʱ��������" << errbuf << endl;
				return 0;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
				{
					SetColor(14,0);
					cout << " IP��";
					printIP(IPPacket->SendIP);
					cout << endl;
					cout << " MAC��";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
				
			}
		}
	}
}