#pragma once
#include <Winsock2.h>
#include "pcap.h"
#include "stdio.h"
#include <string.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

#pragma pack(1)//字节对齐方式

typedef struct FrameHeader_t {		//帧首部
	BYTE DesMAC[6];					//目的地址
	BYTE SrcMAC[6];					//源地址
	WORD FrameType;					//帧类型
}FrameHeader_t;

typedef struct IPHeader_t {	//IP首部
	BYTE Ver_HLen;			//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;				//服务类型
	WORD TotalLen;			//总长度
	WORD ID;				//标识
	WORD Flag_Segment;		//标志 片偏移
	BYTE TTL;				//生存周期
	BYTE Protocol;			//协议
	WORD Checksum;			//头部校验和
	u_int SrcIP;			//源IP
	u_int DstIP;			//目的IP
}IPHeader_t;

typedef struct ARPFrame_t {	//IP首部
	FrameHeader_t FrameHeader;
	WORD HardwareType;		//硬件类型
	WORD ProtocolType;		//协议类型
	BYTE HLen;				//硬件地址长度
	BYTE PLen;				//协议地址长度
	WORD Operation;			//操作类型
	BYTE SendHa[6];			//发送方MAC地址
	DWORD SendIP;			//发送方IP地址
	BYTE RecvHa[6];			//接收方MAC地址
	DWORD RecvIP;			//接收方IP地址
}ARPFrame_t;

typedef struct Data_t {		//数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

typedef struct ICMP {//ICMP报文
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()//恢复缺省对齐方式

class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};

class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};

class Routerlog //日志
{
public:
	int index;//索引
	char type[5];//类型（arp ip）
	ipitem ip;
	arpitem arp;
	Routerlog()
	{
		fp = fopen("log.txt", "a+");//文件以及打开方式
	}
	~Routerlog()
	{
		fclose(fp);
	}
	static int num;
	static Routerlog diary[50];
	static FILE* fp;
	static void WritelogARP(ARPFrame_t* t)
	{
		fprintf(fp, "ARP\t");
		in_addr addr;
		addr.s_addr = t->SendIP;
		char* temp = inet_ntoa(addr);
		fprintf(fp, "IP:\t");
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "MAC:\t");
		for (int i = 0; i < 6; i++)
		{
			fprintf(fp, "%02x:", t->SendHa[i]);
		}
		fprintf(fp, "\n");
	}
	static void WritelogIP(const char* a, Data_t* t)
	{
		fprintf(fp, "IP\t");
		fprintf(fp, a);
		fprintf(fp, "\t");
		in_addr addr;
		addr.s_addr = t->IPHeader.SrcIP;
		char* temp = inet_ntoa(addr);
		fprintf(fp, "源IP：\t");
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "目的IP：\t");
		addr.s_addr = t->IPHeader.DstIP;
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "源MAC：\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.SrcMAC[i]);
		fprintf(fp, "目的MAC：\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.DesMAC[i]);
		fprintf(fp, "\n");
	}
	static void print()
	{
		for (int i = 0; i < num; i++)
		{
			printf("%d ", diary[i].index);
			printf("%s\t ", diary[i].type);
			if (strcmp(diary[i].type, "ARP") == 0)
			{
				in_addr addr;
				addr.s_addr = diary[i].arp.ip;
				char* temp = inet_ntoa(addr);
				printf("%s\t", temp);
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].arp.mac[i]);
				}
			}
			else if (strcmp(diary[i].type, "IP") == 0)
			{
				in_addr addr;
				addr.s_addr = diary[i].ip.sip;
				char* temp = inet_ntoa(addr);
				printf("源IP：%s\t", temp);
				addr.s_addr = diary[i].ip.dip;
				temp = inet_ntoa(addr);
				printf("目的IP：%s\t", temp);
				printf("源MAC: ");
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].ip.smac[i]);
				}
				printf("目的MAC: ");
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].ip.dmac[i]);
				}
			}
		}
	}
};
