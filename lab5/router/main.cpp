#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
#include "pcap.h"
#include "stdio.h"
#include <string.h>
#include "header.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

void SetColor(int fore = 7, int back = 0) {
	unsigned char m_color = fore;
	m_color += (back << 4);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), m_color);
	return;
}

char ip[10][20];
char mask[10][20];
BYTE selfmac[6];
pcap_t* adhandle;
//多线程
HANDLE hThread;
DWORD dwThreadId;
int n;
int Routerlog::num = 0;
Routerlog Routerlog::diary[50] = {};
FILE* Routerlog::fp = nullptr;
Routerlog LT;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

void getMac(DWORD ip0, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//将APRFrame.FrameHeader.DesMAC设置为广播地址
	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
		ARPFrame.RecvHa[i] = 0;//将ARPFrame.RecvHa设置为0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);	//帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);			//协议类型为IP
	ARPFrame.HLen = 6;								//硬件地址长度为6
	ARPFrame.PLen = 4;								//协议地址长为4
	ARPFrame.Operation = htons(0x0001);				//操作为ARP请求
	//将ARPFrame.SendIP设置为本机网卡上绑定的IP地址
	ARPFrame.SendIP = inet_addr(ip[0]);
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = ip0;
	if (adhandle == nullptr)
	{
		SetColor(12, 0);
		printf("网卡接口打开错误\n");
	}
	else
	{
		if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//发送错误处理
			SetColor(12, 0);
			printf("发送错误\n");
			return;
		}
		else
		{
			//发送成功
			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{
						if (ntohs(IPPacket->Operation) == 0x0002)
						{
							LT.WritelogARP(IPPacket);
							//输出源MAC地址
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

#pragma pack(1)
class RouterItem//路由表表项
{
public:
	DWORD mask;					//掩码
	DWORD net;					//目的网络
	DWORD nextip;				//下一跳
	BYTE nextmac[6];
	int index;					//第几条
	int type;					//0为直接连接，1为用户添加
	RouterItem* nextitem;		//采用链表形式存储
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//全部初始化为0
	}
	void PrintItem()//打印表项内容：掩码、目的网络、下一跳IP、类型
	{
		SetColor(14, 0);
		in_addr addr;
		printf("%d\t", index);
		addr.s_addr = mask;
		char* temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = net;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = nextip;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		printf("%d\n", type);
	}
};
#pragma pack()

#pragma pack(1)
class RouterTable//路由表
{
public:
	RouterItem* head;
	RouterItem* tail;
	int num;//条数
	RouterTable()//初始化，添加直接相连的网络
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//本机网卡的ip和掩码进行按位与即为所在网络
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;//0表示直接连接，不可删除
			this->RouterAdd(temp);
		}
	}
	void RouterAdd(RouterItem* a)//路由表的添加
	{
		RouterItem* pointer;
		if (!a->type)
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else//按照掩码由长至短找到合适的位置
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
			{
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				{
					break;
				}
			}
			a->nextitem = pointer->nextitem;
			pointer->nextitem = a;
		}
		RouterItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)
		{
			p->index = i;
		}
		num++;
	}
	void RouterRemove(int index)//路由表的删除
	{
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					//SetColor(12, 0);
					printf("该项不可删除\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}
		SetColor(12, 0);
		printf("无该表项\n");
	}
	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}
	DWORD RouterFind(DWORD ip)//查找最长前缀，返回下一跳的ip
	{
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			if ((t->mask & ip) == t->net)
			{
				return t->nextip;
			}
		}
		return -1;
	}
};
#pragma pack()

#pragma pack(1)
class ArpTable//ARP表
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;
	static void InsertArp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		getMac(ip, arptable[num].mac);
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}
	static int FindArp(DWORD ip, BYTE mac[6])
	{
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++)
		{
			if (ip == arptable[i].ip)
			{
				memcpy(mac, arptable[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
}arptable[50];
#pragma pack()

int ArpTable::num = 0;

void SetCheckSum(Data_t* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//每16位为一组
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//结果取反
}

bool CheckSum(Data_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//如果溢出，则进行回卷
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}

void resend(ICMP_t data, BYTE desmac[])
{
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//源MAC为本机MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//目的MAC为下一跳MAC
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL < 0)
	{
		return;
	}
	SetCheckSum(temp);//重新设置校验和
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//发送数据报
	if (rtn == 0)
	{
		LT.WritelogIP("转发", temp);
	}
}

//线程函数
DWORD WINAPI Thread(LPVOID lparam)
{
	RouterTable RT = *(RouterTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
			if (rtn)//接收到消息
			{
				break;
			}
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (Compare(header->DesMAC, selfmac))//目的mac是自己的mac
		{
			if (ntohs(header->FrameType) == 0x0800)//收到IP
			{
				Data_t* data = (Data_t*)pkt_data;
				LT.WritelogIP("接收", data);
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);//查找是否有对应表项
				if (IFip == -1)
				{
					continue;
				}
				if (CheckSum(data))//如果校验和不正确，则直接丢弃不进行处理
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							//ICMP报文包含IP数据包报头和其它内容
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (IFip == 0)
							{
								//如果ARP表中没有所需内容，则需要获取ARP
								if (!ArpTable::FindArp(dstip, mac))
								{
									ArpTable::InsertArp(dstip, mac);
								}
								resend(temp, mac);
							}

							else if (IFip != -1)//非直接投递，查找下一条IP的MAC
							{
								if (!ArpTable::FindArp(IFip, mac))
								{
									ArpTable::InsertArp(IFip, mac);
								}
								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}


int main()
{
	pcap_if_t* alldevs;				//指向设备链表首部的指针
	pcap_if_t* ptr;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区	
	int num = 0;					//接口数量

	/*获取本地机器设备列表*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf("获取本机设备错误：%s\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}

	int t = 0;
	//显示接口列表
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		num++;
		SetColor(7, 0);
		printf("网卡 %d\t%s \n", num, ptr->name);
		printf("描述信息：%s \n", ptr->description);
		pcap_addr_t* a;
		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET && a->addr != NULL)
			{
				SetColor(14, 0);
				printf("  Address Family Name:AF_INET\n");
				printf("  IP地址：  %s \n", inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
				printf("  子网掩码：%s \n", inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr));
				strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
			}
			else if (a->addr->sa_family == AF_INET6)
			{
				printf("  Address Family Name:AF_INET6\n");
			}
			t++;
		}
		printf("----------------------------------------------------------------------------------------------------------\n");
	}

	if (num == 0)
	{
		printf("无可用接口\n");
		return 0;
	}

	SetColor(13, 0);
	printf("请输入要打开的网络接口号：");
	scanf("%d", &n);
	// 跳转到选中的网络接口号
	ptr = alldevs;
	for (int i = 1; i < n; i++)
	{
		ptr = ptr->next;
	}

	adhandle = pcap_open(ptr->name,		//设备名
		65536,							//要捕获的数据包的部分
		PCAP_OPENFLAG_PROMISCUOUS,		//混杂模式
		1000,							//超时时间
		NULL,							//远程机器验证
		errbuf							//错误缓冲池
	);
	if (adhandle == NULL)
	{
		SetColor(12, 0);
		printf("产生错误，无法打开设备\n");
		return 0;
	}
	else
	{
		SetColor(10, 0);
		printf("监听：%s\n", ptr->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		SetColor(10, 0);
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}


	//伪造ARP报文获取本机MAC
	memset(selfmac, 0, sizeof(selfmac));
	//设置ARP帧的内容
	ARPFrame_t ARPFrame;//ARP初始帧的声明

	//组装报文
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;	//将APRFrame.FrameHeader.DesMAC设置为广播地址
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;	//将APRFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址
		ARPFrame.RecvHa[i] = 0x00;				//将ARPFrame.RecvHa设置为0表示目的地址未知
		ARPFrame.SendHa[i] = 0x0f;				//将ARPFrame.SendHa设置为本机网卡的MAC地址
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);	// 帧类型为ARP
	ARPFrame.HardwareType = htons(0x0001);			// 硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);			// 协议类型为IP
	ARPFrame.HLen = 6;								// 硬件地址长度为6
	ARPFrame.PLen = 4;								// 协议地址长为4
	ARPFrame.Operation = htons(0x0001);				// 操作为ARP请求
	ARPFrame.SendIP = inet_addr("122.122.122.122");//源IP地址设置为虚拟的IP地址 112.112.112.112.112.112
	//将ARPFrame.RecvIP设置为请求的IP地址
	ARPFrame.RecvIP = inet_addr(ip[0]);
	//用网卡发送ARPFrame中的内容，报文长度为sizeof(ARPFrame_t)，如果发送成功，返回0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		SetColor(12, 0);
		printf("发送失败，退出程序\n");
		return -1;
	}
	else
	{
		SetColor(10, 0);
		printf("ARP请求发送成功\n");
	}
	// 声明即将捕获的ARP帧
	ARPFrame_t* IPPacket;
	// 开始进行捕获
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	while (1)//可能会有多条消息
	{
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			for (int i = 0; i < 6; i++)
			{
				selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//如果帧类型为ARP并且操作为ARP应答
			{
				LT.WritelogARP(IPPacket);
				SetColor(14, 0);
				printf(" Mac地址：\t");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
		else if (rtn == 0)
		{
			SetColor(12, 0);
			printf("  没有捕获到数据报\n");
		}
	}
	RouterTable RT;
	hThread = CreateThread(NULL, NULL, Thread, LPVOID(&RT), 0, &dwThreadId);
	char op[50];
	char netip[50];
	char mask[50];
	char nextip[50];
	char help[50] = "help";
	char print[50] = "routeprint";
	char add[50] = "routeadd";
	char remove[50] = "routeremove";
	char quit[50] = "quit";
	while (1)
	{
		SetColor(13, 0);
		printf("请输入你想要进行的操作：");
		scanf("%s", op);
		if (!strcmp(op, help))
		{
			SetColor(14, 0);
			printf("打印路由表\trouteprint\n");
			printf("添加路由表项\trouteadd\n");
			printf("删除路由表项\trouteremove\n");
			printf("退出\tquit\n");
		}
		else if (!strcmp(op,print))
		{
			RT.print();
		}
		else if (!strcmp(op, add))
		{
			RouterItem ri;
			SetColor(13, 0);
			scanf("%s %s %s", netip, mask, nextip);
			ri.net = inet_addr(netip);
			ri.mask = inet_addr(mask);
			ri.nextip = inet_addr(nextip);
			ri.type = 1;
			RT.RouterAdd(&ri);
		}
		else if (!strcmp(op, remove))
		{
			SetColor(13, 0);
			printf("请输入删除表项编号：");
			int index;
			scanf("%d", &index);
			RT.RouterRemove(index);
		}
		else if (!strcmp(op, quit))
		{
			break;
		}
		else
		{
			SetColor(12, 0);
			printf("无效操作，请重新选择\n");
		}
	}

	pcap_close(adhandle);
	return 0;
}