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
//���߳�
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
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
		ARPFrame.RecvHa[i] = 0;//��ARPFrame.RecvHa����Ϊ0
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);	//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);			//Э������ΪIP
	ARPFrame.HLen = 6;								//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;								//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);				//����ΪARP����
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = ip0;
	if (adhandle == nullptr)
	{
		SetColor(12, 0);
		printf("�����ӿڴ򿪴���\n");
	}
	else
	{
		if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//���ʹ�����
			SetColor(12, 0);
			printf("���ʹ���\n");
			return;
		}
		else
		{
			//���ͳɹ�
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
							//���ԴMAC��ַ
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
class RouterItem//·�ɱ����
{
public:
	DWORD mask;					//����
	DWORD net;					//Ŀ������
	DWORD nextip;				//��һ��
	BYTE nextmac[6];
	int index;					//�ڼ���
	int type;					//0Ϊֱ�����ӣ�1Ϊ�û����
	RouterItem* nextitem;		//����������ʽ�洢
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//ȫ����ʼ��Ϊ0
	}
	void PrintItem()//��ӡ�������ݣ����롢Ŀ�����硢��һ��IP������
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
class RouterTable//·�ɱ�
{
public:
	RouterItem* head;
	RouterItem* tail;
	int num;//����
	RouterTable()//��ʼ�������ֱ������������
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//����������ip��������а�λ�뼴Ϊ��������
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;//0��ʾֱ�����ӣ�����ɾ��
			this->RouterAdd(temp);
		}
	}
	void RouterAdd(RouterItem* a)//·�ɱ�����
	{
		RouterItem* pointer;
		if (!a->type)
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else//���������ɳ������ҵ����ʵ�λ��
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
	void RouterRemove(int index)//·�ɱ��ɾ��
	{
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					//SetColor(12, 0);
					printf("�����ɾ��\n");
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
		printf("�޸ñ���\n");
	}
	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}
	DWORD RouterFind(DWORD ip)//�����ǰ׺��������һ����ip
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
class ArpTable//ARP��
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
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//���ȡ��
}

bool CheckSum(Data_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
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
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//Ŀ��MACΪ��һ��MAC
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL < 0)
	{
		return;
	}
	SetCheckSum(temp);//��������У���
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//�������ݱ�
	if (rtn == 0)
	{
		LT.WritelogIP("ת��", temp);
	}
}

//�̺߳���
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
			if (rtn)//���յ���Ϣ
			{
				break;
			}
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (Compare(header->DesMAC, selfmac))//Ŀ��mac���Լ���mac
		{
			if (ntohs(header->FrameType) == 0x0800)//�յ�IP
			{
				Data_t* data = (Data_t*)pkt_data;
				LT.WritelogIP("����", data);
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);//�����Ƿ��ж�Ӧ����
				if (IFip == -1)
				{
					continue;
				}
				if (CheckSum(data))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							//ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (IFip == 0)
							{
								//���ARP����û���������ݣ�����Ҫ��ȡARP
								if (!ArpTable::FindArp(dstip, mac))
								{
									ArpTable::InsertArp(dstip, mac);
								}
								resend(temp, mac);
							}

							else if (IFip != -1)//��ֱ��Ͷ�ݣ�������һ��IP��MAC
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
	pcap_if_t* alldevs;				//ָ���豸�����ײ���ָ��
	pcap_if_t* ptr;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������	
	int num = 0;					//�ӿ�����

	/*��ȡ���ػ����豸�б�*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		printf("��ȡ�����豸����%s\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}

	int t = 0;
	//��ʾ�ӿ��б�
	for (ptr = alldevs; ptr != NULL; ptr = ptr->next)
	{
		num++;
		SetColor(7, 0);
		printf("���� %d\t%s \n", num, ptr->name);
		printf("������Ϣ��%s \n", ptr->description);
		pcap_addr_t* a;
		for (a = ptr->addresses; a != NULL; a = a->next)
		{
			if (a->addr->sa_family == AF_INET && a->addr != NULL)
			{
				SetColor(14, 0);
				printf("  Address Family Name:AF_INET\n");
				printf("  IP��ַ��  %s \n", inet_ntoa(((struct sockaddr_in*)(a->addr))->sin_addr));
				printf("  �������룺%s \n", inet_ntoa(((struct sockaddr_in*)(a->netmask))->sin_addr));
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
		printf("�޿��ýӿ�\n");
		return 0;
	}

	SetColor(13, 0);
	printf("������Ҫ�򿪵�����ӿںţ�");
	scanf("%d", &n);
	// ��ת��ѡ�е�����ӿں�
	ptr = alldevs;
	for (int i = 1; i < n; i++)
	{
		ptr = ptr->next;
	}

	adhandle = pcap_open(ptr->name,		//�豸��
		65536,							//Ҫ��������ݰ��Ĳ���
		PCAP_OPENFLAG_PROMISCUOUS,		//����ģʽ
		1000,							//��ʱʱ��
		NULL,							//Զ�̻�����֤
		errbuf							//���󻺳��
	);
	if (adhandle == NULL)
	{
		SetColor(12, 0);
		printf("���������޷����豸\n");
		return 0;
	}
	else
	{
		SetColor(10, 0);
		printf("������%s\n", ptr->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		SetColor(10, 0);
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}


	//α��ARP���Ļ�ȡ����MAC
	memset(selfmac, 0, sizeof(selfmac));
	//����ARP֡������
	ARPFrame_t ARPFrame;//ARP��ʼ֡������

	//��װ����
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
		ARPFrame.RecvHa[i] = 0x00;				//��ARPFrame.RecvHa����Ϊ0��ʾĿ�ĵ�ַδ֪
		ARPFrame.SendHa[i] = 0x0f;				//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);	// ֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);			// Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);			// Э������ΪIP
	ARPFrame.HLen = 6;								// Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;								// Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);				// ����ΪARP����
	ARPFrame.SendIP = inet_addr("122.122.122.122");//ԴIP��ַ����Ϊ�����IP��ַ 112.112.112.112.112.112
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(ip[0]);
	//����������ARPFrame�е����ݣ����ĳ���Ϊsizeof(ARPFrame_t)��������ͳɹ�������0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		SetColor(12, 0);
		printf("����ʧ�ܣ��˳�����\n");
		return -1;
	}
	else
	{
		SetColor(10, 0);
		printf("ARP�����ͳɹ�\n");
	}
	// �������������ARP֡
	ARPFrame_t* IPPacket;
	// ��ʼ���в���
	pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	while (1)//���ܻ��ж�����Ϣ
	{
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			for (int i = 0; i < 6; i++)
			{
				selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				LT.WritelogARP(IPPacket);
				SetColor(14, 0);
				printf(" Mac��ַ��\t");
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
			printf("  û�в������ݱ�\n");
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
		printf("����������Ҫ���еĲ�����");
		scanf("%s", op);
		if (!strcmp(op, help))
		{
			SetColor(14, 0);
			printf("��ӡ·�ɱ�\trouteprint\n");
			printf("���·�ɱ���\trouteadd\n");
			printf("ɾ��·�ɱ���\trouteremove\n");
			printf("�˳�\tquit\n");
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
			printf("������ɾ�������ţ�");
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
			printf("��Ч������������ѡ��\n");
		}
	}

	pcap_close(adhandle);
	return 0;
}