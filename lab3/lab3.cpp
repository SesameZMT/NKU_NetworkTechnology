#include <Winsock2.h>
#include<iostream>
#include <ws2tcpip.h>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")//表示链接的时侯找ws2_32.lib
#pragma warning( disable : 4996 )//要使用旧函数
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
struct FrameHeader_t //帧首部
{
	BYTE DesMAC[6];  //目的地址
	BYTE SrcMAC[6];  //源地址
	WORD FrameType;  //帧类型
};

struct ARPFrame_t               //ARP帧
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
	pcap_if_t* alldevs;//指向设备列表首部的指针
	pcap_if_t* ptr;
	pcap_addr_t* a;
	char errbuf[PCAP_ERRBUF_SIZE];//错误信息缓冲区
	ARPFrame_t ARPFrame;
	ARPFrame_t* IPPacket;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;

	int index = 0;
	DWORD SendIP;
	DWORD RevIP;

	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		SetColor(12, 0);
		cout << "获取网络接口时发生错误:" << errbuf << endl;
		return 0;
	}
	//显示接口列表
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		SetColor(7,0);
		cout << "网卡" << index + 1 << "\t" << ptr->name << endl;
		cout << "描述信息：" << ptr->description << endl;

		for (a = ptr->addresses; a != NULL; a = a->next)
		{

			if (a->addr->sa_family == AF_INET)
			{
				SetColor(14, 0);
				cout << "  IP地址：" << inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr) << endl;
				cout << "  子网掩码：" << inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr) << endl;

			}
		}

		index++;
	}

	int num;
	SetColor(13, 0);
	cout << "请选要打开的网卡号：";
	cin >> num;
	ptr = alldevs;
	for (int i = 1; i < num; i++)
	{
		ptr = ptr->next;
	}

	pcap_t* pcap_handle = pcap_open(ptr->name, 1024, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);//打开网卡
	if (pcap_handle == NULL)
	{
		SetColor(12, 0);
		cout << "打开网卡时发生错误：" << errbuf << endl;
		return 0;
	}
	else
	{
		SetColor(10,0);
		cout << "成功打开该网卡" << endl;
	}

	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xFF;//将APRFrame.FrameHeader.DesMAC设置为广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
		ARPFrame.RecvHa[i] = 0;//将ARPFrame.RecvHa设置为0表示目的地址未知
		ARPFrame.SendHa[i] = 0x66;//将ARPFrame.SendHa设置为本机网卡的MAC地址
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);//协议类型为IP
	ARPFrame.HLen = 6;//硬件地址长度为6
	ARPFrame.PLen = 4; // 协议地址长为4
	ARPFrame.Operation = htons(0x0001);//操作为ARP请求
	SendIP = ARPFrame.SendIP = htonl(0x70707070);//源IP地址设置为虚拟的IP地址 112.112.112.112.112.112

	//将所选择的网卡的IP设置为请求的IP地址
	for (a = ptr->addresses; a != NULL; a = a->next)
	{
		if (a->addr->sa_family == AF_INET)
		{
			RevIP = ARPFrame.RecvIP = inet_addr(inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
		}
	}
	pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
	SetColor(10,0);
	cout << "ARP请求发送成功" << endl;
	while (true)
	{
		int rtn = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
		if (rtn == -1)
		{
			SetColor(12, 0);
			cout << "  捕获数据包时发生错误：" << errbuf << endl;
			return 0;
		}
		else
		{
			if (rtn == 0)
			{
				SetColor(12, 0);
				cout << "  没有捕获到数据报" << endl;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)//判断是不是一开始发的包
				{
					SetColor(14,0);
					cout << " IP：";
					printIP(IPPacket->SendIP);
					cout << endl;
					cout << " MAC：";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
			}
		}
	}

	//向网络发送数据包
	SetColor(13,0);
	cout << "\n" << endl;
	cout << "向网络发送一个数据包" << endl;
	cout << "请求IP地址:";
	char str[32];
	cin >> str;
	RevIP = ARPFrame.RecvIP = inet_addr(str);
	SendIP = ARPFrame.SendIP = IPPacket->SendIP;//将本机IP赋值给数据报的源IP
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = ARPFrame.FrameHeader.SrcMAC[i] = IPPacket->SendHa[i];
	}

	if (pcap_sendpacket(pcap_handle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		SetColor(12, 0);
		cout << "ARP请求发送失败" << endl;
	}
	else
	{
		SetColor(10,0);
		cout << "ARP请求发送成功" << endl;

		while (true)
		{
			int n = pcap_next_ex(pcap_handle, &pkt_header, &pkt_data);
			if (n == -1)
			{
				SetColor(12, 0);
				cout << "  捕获数据包时发生错误：" << errbuf << endl;
				return 0;
			}
			else
			{
				IPPacket = (ARPFrame_t*)pkt_data;
				if (IPPacket->RecvIP == SendIP && IPPacket->SendIP == RevIP)
				{
					SetColor(14,0);
					cout << " IP：";
					printIP(IPPacket->SendIP);
					cout << endl;
					cout << " MAC：";
					printMAC(IPPacket->SendHa);
					cout << endl;
					break;
				}
				
			}
		}
	}
}