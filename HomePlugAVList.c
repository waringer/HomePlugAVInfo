/*
	HomePlugAVList.c version 0.0.1.0

	Copyright (C) 2013 Holger Wolff <waringer@gmail.com>.
	All rights reserved.
*/

#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define HomePlugAVList_VERSION "0.0.1.1"

static char AtherosMac[6]	= {0x00, 0xb0, 0x52, 0x00, 0x00, 0x01};
//static char BroadcastMac[6]	= {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char HomePlugAVType[2]	= {0x88, 0xe1};
static char AtherosVendor[3]	= {0x00, 0xb0, 0x52};

struct NetFrame
{
	int		netfd;
	u_int	buflen;
	u_char	*framebuf;
};

/* bpf filter (only HomePlugAVType) */
struct bpf_insn insns[] = {
	 BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x88e1, 0, 1),
//	 BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, HomePlugAVType, 0, 1),
	 BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
	 BPF_STMT(BPF_RET+BPF_K, 0)
};

struct StationInfo
{
	u_char	Mac[6];
	u_int	EquipmentID;
	u_int	AvgPhyTXRate;
	u_int	AvgPhyRXRate;
	u_char	FirstBrigedMac[6];
};

struct NetworkInfo
{
	u_char	NetworkID[7];
	u_int	ShortID;
	u_int	EquipmentID;
	u_int	Role;
	u_char	CCoMAC[6];
	u_int	CCoEquipmentID;
	u_int	StationCount;
	struct	StationInfo *Stations;
};

struct NetInfo
{
	u_int	NetworkCount;
	struct	NetworkInfo *Networks;
};

u_short ex_word(u_char *ptr) {return ntohs(*((u_short*)ptr));}

char *format_mac_addr(u_char *addr, char *macbuf)
{
	sprintf(macbuf, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return macbuf;
}

char *format_net_id(u_char *netid, char *NetworkID)
{
	sprintf(NetworkID, "%02x:%02x:%02x:%02x:%02x:%02x:%02x", netid[0], netid[1], netid[2], netid[3], netid[4], netid[5], netid[6]);
	return NetworkID;
}

void BuildSendBaseFrame(u_char *outframe, char *DestMac)
{
	u_int i;

	/* set destination mac */
	memcpy(&outframe[0], DestMac, 6);

	for (i = 6; i < 12; i++)
		outframe[i] = 0x00;	/* let os set the source address automatically */

	/* Type Homeplug AV */
	memcpy(&outframe[12], HomePlugAVType, 2);

	/* MAC Management Header Placeholder */
	outframe[14] = 0x00;
	outframe[15] = 0x00;
	outframe[16] = 0x00;

	/* Vendor MME */
	memcpy(&outframe[17], AtherosVendor, 3);
}

void SendDeviceVersion(int netfd, char *DeviceMac)
{
	u_int i;
	u_char outframe[64];
	
	if ((DeviceMac[0] == 0) & (DeviceMac[1] == 0) & (DeviceMac[2] == 0) & (DeviceMac[3] == 0) & (DeviceMac[4] == 0) & (DeviceMac[5] == 0))
	    BuildSendBaseFrame(&outframe[0], AtherosMac);
	else
	    BuildSendBaseFrame(&outframe[0], DeviceMac);

	/* MAC Management Header */
	outframe[14] = 0x00; // Version 1
	outframe[15] = 0x00; // Get Device/SW Version Request
	outframe[16] = 0xa0;

	for (i = 20; i < 64; i++)
		outframe[i] = 0x00;	/* fill */

	/* write out packet */
	write(netfd, outframe, 64);
}

void SendNetworkInfo(int netfd, char *DeviceMac)
{
	u_int i;
	u_char outframe[64];

	BuildSendBaseFrame(&outframe[0], DeviceMac);

	/* MAC Management Header */
	outframe[14] = 0x00; // Version 1
	outframe[15] = 0x38; // Network Info Request
	outframe[16] = 0xa0;

	for (i = 20; i < 64; i++)
		outframe[i] = 0x00;	/* fill */

	/* write out packet */
	write(netfd, outframe, 64);
}

u_char* GetNetworkAnswer(struct NetFrame net, u_int waittime, ushort ReqType)
{
	struct	bpf_hdr *header;
	struct	timeval	start;
	struct	timeval	end;
	struct	timeval timeout;

	u_char	*frameptr;
	int		sec;
	fd_set	set;

	FD_ZERO(&set); /* clear the set */
	FD_SET(net.netfd, &set); /* add our file descriptor to the set */

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;

	/* read responses */
	gettimeofday(&start, NULL);
	do
	{
		int rl = select(net.netfd + 1, &set, NULL, NULL, &timeout);
		if (rl == 1)
		{		
			read(net.netfd, net.framebuf, net.buflen);
			header = (struct bpf_hdr*)net.framebuf;
			frameptr = net.framebuf + header->bh_hdrlen;

			if (ReqType == ex_word(&frameptr[15]))
				return frameptr;
		}

		gettimeofday(&end, NULL);
		sec = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
	} while  (sec < waittime) ;

	return 0;
}

int GetDeviceVersion(struct NetFrame net, u_int waittime, char *mac, char *DeviceVerion)
{
	/* read responses */
	u_char *frameptr = GetNetworkAnswer(net, waittime, 0x1a0);
	if (0 != frameptr)
	{
	    memcpy(DeviceVerion, &frameptr[23], frameptr[22]);
	    memcpy(mac, &frameptr[6], 6);
	    return 1;
	}

	return 0;
}

int GetNetworkInfo(struct NetFrame net, u_int waittime, struct NetInfo *Net)
{
	/* read responses */
	u_int	framepos;
	u_char	*frameptr = GetNetworkAnswer(net, waittime, 0x39a0);
	if (0 != frameptr)
	{
	    u_int	i, j;

	    framepos = 20;
	    Net->NetworkCount = frameptr[framepos++];
	    if (Net->NetworkCount >= 1)
	    {
		Net->Networks = malloc(Net->NetworkCount * sizeof(struct NetworkInfo));
		for(i = 0; i < Net->NetworkCount; i++)
		{
		    memcpy(Net->Networks[i].NetworkID, &frameptr[framepos], 7);
		    framepos = framepos + 7;
		    Net->Networks[i].ShortID = frameptr[framepos++];
		    Net->Networks[i].EquipmentID = frameptr[framepos++];
		    Net->Networks[i].Role = frameptr[framepos++];
		    memcpy(Net->Networks[i].CCoMAC, &frameptr[framepos], 6);
		    framepos = framepos + 6;
		    Net->Networks[i].CCoEquipmentID = frameptr[framepos++];
		    Net->Networks[i].StationCount = frameptr[framepos++];
		    Net->Networks[i].Stations = malloc(Net->Networks[i].StationCount * sizeof(struct StationInfo));
		    for(j = 0; j < Net->Networks[i].StationCount; j++)
		    {
			memcpy(Net->Networks[i].Stations[j].Mac, &frameptr[framepos], 6);
			framepos = framepos + 6;
			Net->Networks[i].Stations[j].EquipmentID = frameptr[framepos++];
			memcpy(Net->Networks[i].Stations[j].FirstBrigedMac, &frameptr[framepos], 6);
			framepos = framepos + 6;
			Net->Networks[i].Stations[j].AvgPhyTXRate = frameptr[framepos++];
			Net->Networks[i].Stations[j].AvgPhyRXRate = frameptr[framepos++];
		    }
		}
	    }

	    return 1;
	}

	return 0;
}

void SetupNetDevice(char *bpfn, struct NetFrame *net, char *ifname)
{
	struct	ifreq		ifr;
	struct	bpf_program	filter;

	/* Open bpf device */
	net->netfd = open(bpfn, O_RDWR);

	if (net->netfd == -1) {
		fprintf(stderr, "Cannot open %s\n", bpfn);
		exit(0);
	}

	/* Read buffer length */
	if (ioctl(net->netfd, BIOCGBLEN, &(net->buflen)) == -1) {
		fprintf(stderr, "ioctl(BIOCGBLEN) error!\n");
		exit(0);
	}

	/* Allocate buffer */
	if (!(net->framebuf = (u_char*)malloc((size_t)net->buflen))) {
		fprintf(stderr, "Cannot malloc() packet buffer!\n");
		exit(0);
	}

	/* Bind to interface */
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(net->netfd, BIOCSETIF, &ifr) == -1) {
		fprintf(stderr, "ioctl(BIOCSETIF) error!\n");
		exit(0);
	}

	/* Set filter */
	filter.bf_len = sizeof(insns) / sizeof(insns[0]);
	filter.bf_insns = insns;

	if (ioctl(net->netfd, BIOCSETF, &filter) == -1) {
		fprintf(stderr, "ioctl(BIOCSETF) error!\n");
		exit(0);
	}

	/* Set immediate mode */
	u_int i = 1;	
	if (ioctl(net->netfd, BIOCIMMEDIATE, &i) == -1) {
		fprintf(stderr, "ioctl(BIOCIMMEDIATE) error!\n");
		exit(0);
	}

	/* We don't want to see local packets */
	i = 0;
	if (ioctl(net->netfd, BIOCGSEESENT, &i) == -1) {
		fprintf(stderr, "ioctl(BIOCGSEESENT) error!\n");
		exit(0);
	}
}

void CloseNetDevice(struct NetFrame *net)
{
	free(net->framebuf);

	/* Close bpf device */
	close(net->netfd);
}

void usage(void) {
	
	printf("%s",
	       "\nHomePlug-AV Device List version " HomePlugAVList_VERSION " by Holger Wolff <waringer@gmail.com>\n\n"
	       "Usage:   HomePlugAVList [-h] [-b device] [-m mac] [-c count] interface\n\n"
	
		   "	-b device	use device (default is /dev/bpf0)\n"
		   "	-m mac		mac to use (default is to search for a mac)\n"
		   "	-c count	how many times try to connect if no response is received (default is 5)\n"
		   "	-h		display this help\n\n"
		   
		   "         ...\n\n");
}

void ParseOptions(int argc, char *argv[], char *bpfn, char *ifname, u_char *DeviceMac, u_int *TryCount)
{
	int ch, i;
	u_char mac[18];
	
	/* Parse command line options */
	while ((ch = getopt(argc, argv, "b:m:c:h")) != -1) {
	 
		 switch (ch) {
			case 'b':
				strncpy(bpfn, optarg, 32);
				break;
			case 'c':
				sscanf(optarg, "%3u", TryCount);
				break;
			case 'm':
				strncpy(mac, optarg, 17);
				mac[17] = 0;
//				fprintf(stderr, "l:%u", strlen(mac));
				if (strlen(mac) == 17)
				{
				    if (strchr(mac, ':') != NULL)
					sscanf(mac, "%1h1hx:%1h1hx:%1h1hx:%1h1hx:%1h1hx:%1h1hx", (u_char *)&DeviceMac[0], (u_char *)&DeviceMac[1], (u_char *)&DeviceMac[2], (u_char *)&DeviceMac[3], (u_char *)&DeviceMac[4], (u_char *)&DeviceMac[5]);
				    else
					if (strchr(mac, '-') != NULL)
					    sscanf(mac, "%1h1hx-%1h1hx-%1h1hx-%1h1hx-%1h1hx-%1h1hx", (u_char *)&DeviceMac[0], (u_char *)&DeviceMac[1], (u_char *)&DeviceMac[2], (u_char *)&DeviceMac[3], (u_char *)&DeviceMac[4], (u_char *)&DeviceMac[5]);
				}
				else
				    if (strlen(mac) == 12)
				    {
					u_char digit[3] = {0, 0, 0};
					for(i = 0; i < 6; i++)
					{
					    strncpy(digit, &mac[i * 2], 2);
					    digit[2] = 0;
					    sscanf(digit, "%1h1hx", (u_char *)&DeviceMac[i]);
					}
				    }
				    
				break;
			case '?':
			case 'h':
			default:
				usage();
				exit(0);
		 }
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
		exit(0);
	}

	strncpy(ifname, argv[0], 8);
}

int main(int argc, char *argv[]) {
	struct	NetFrame	net;
	struct	NetInfo		HomePlugNetInfo;

	char	ifname[8];
	char	bpfn[32] = "/dev/bpf0";
	u_char	SenderMac[6] = {0,0,0,0,0,0};
	char	DeviceVersion[200];
	char	macbuf[20];
	u_int	TryCounter = 1;
	u_int	MaxTrys = 5;
	u_int	i, j;

	ParseOptions(argc, argv, bpfn, ifname, SenderMac, &MaxTrys);

	SetupNetDevice(bpfn, &net, ifname);

	do
	{
		SendDeviceVersion(net.netfd, SenderMac);
	} while (!GetDeviceVersion(net, 1000000, SenderMac, DeviceVersion) && (TryCounter++ < MaxTrys));


	if ((SenderMac[0] != 0) & (SenderMac[1] != 0) & (SenderMac[2] != 0) & (SenderMac[3] != 0) & (SenderMac[4] != 0) & (SenderMac[5] != 0))
	{
	    printf("- Device MAC :\t\t\t\t%s\n", format_mac_addr(SenderMac, macbuf));
	    printf("- Device Version :\t\t\t%s\n", DeviceVersion);

	    TryCounter = 1;
	    do
	    {
		SendNetworkInfo(net.netfd, SenderMac);
	    } while (!GetNetworkInfo(net, 1000000, &HomePlugNetInfo) && (TryCounter++ < MaxTrys));
	}

	if (HomePlugNetInfo.NetworkCount != 0)
	{
	    char	NetID_Buffer[23];

	    printf("- Network count :\t\t\t%02x\n", HomePlugNetInfo.NetworkCount);
	    for(i = 0; i < HomePlugNetInfo.NetworkCount; i++)
	    {
		printf("- Network %02u ID :\t\t\t%s\n", i, format_net_id(HomePlugNetInfo.Networks[i].NetworkID, NetID_Buffer));
		printf("- Network %02u ShortID :\t\t\t%02x\n", i, HomePlugNetInfo.Networks[i].ShortID);
		printf("- Network %02u EquipmentID :\t\t%02x\n", i, HomePlugNetInfo.Networks[i].EquipmentID);
		printf("- Network %02u Role :\t\t\t%02x\n", i, HomePlugNetInfo.Networks[i].Role);
		printf("- Network %02u CCo MAC :\t\t\t%s\n", i, format_mac_addr(HomePlugNetInfo.Networks[i].CCoMAC, macbuf));
		printf("- Network %02u CCo EquipmentID :\t\t%02x\n", i, HomePlugNetInfo.Networks[i].CCoEquipmentID);
		printf("- Network %02u Station count :\t\t%02x\n", i, HomePlugNetInfo.Networks[i].StationCount);
		for(j = 0; j < HomePlugNetInfo.Networks[i].StationCount; j++)
		{
		    printf("- Network %02u Station %02u MAC :\t\t%s\n", i, j, format_mac_addr(HomePlugNetInfo.Networks[i].Stations[j].Mac, macbuf));
		    printf("- Network %02u Station %02u EquipmentID :\t%02x\n", i, j, HomePlugNetInfo.Networks[i].Stations[j].EquipmentID);
		    printf("- Network %02u Station %02u 1. briged MAC :\t%s\n", i, j, format_mac_addr(HomePlugNetInfo.Networks[i].Stations[j].FirstBrigedMac, macbuf));
		    printf("- Network %02u Station %02u AvgPhyTX Rate :\t%02x\n", i, j, HomePlugNetInfo.Networks[i].Stations[j].AvgPhyTXRate);
		    printf("- Network %02u Station %02u AvgPhyRX Rate :\t%02x\n", i, j, HomePlugNetInfo.Networks[i].Stations[j].AvgPhyRXRate);
		}
	    }
	}

	/* Free memory */
	for(i = 0; i < HomePlugNetInfo.NetworkCount; i++)
	    if (HomePlugNetInfo.Networks[i].Stations != NULL)
		free(HomePlugNetInfo.Networks[i].Stations);

	if (HomePlugNetInfo.NetworkCount > 0)
	    free(HomePlugNetInfo.Networks);

	CloseNetDevice(&net);
}
