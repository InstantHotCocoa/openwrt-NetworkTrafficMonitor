#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <string.h>

struct eth_ip_tcp_hdr
{
	uint8_t eth_dst[6];         /* MAC Destination Address */
	uint8_t eth_src[6];         /* MAC Source Address */
	uint16_t eth_type;          /* Ethernet Type */
	uint8_t ip_ver_hdrlen;      /* Version and Header Length */
	uint8_t ip_dsfield;         /* Differentiated Services Field */
	uint16_t ip_len;            /* Total Length */
	uint16_t ip_id;             /* Identification */
	uint16_t ip_flag_frag;      /* Flags and Fragment offset */
	uint8_t ip_ttl;             /* Time to live */
	uint8_t ip_proto;           /* Protocol */
	uint16_t ip_chksum;         /* Header checksum */
	uint32_t ip_src;            /* IP Source Address */
	uint32_t ip_dst;            /* IP Destination Address */
	uint16_t tcp_srcport;       /* TCP Source Port */
	uint16_t tcp_dstport;       /* TCP Destination Port */
	uint32_t tcp_seq;           /* TCP Sequence number */
	uint32_t tcp_ack;           /* TCP Acknowledgment number */
	uint8_t tcp_hdrlen_flags;   /* TCP Header Length and flags.nonce */
	uint8_t tcp_flags;          /* TCP flags.fin */
	uint16_t tcp_windowsize;    /* TCP window size value */
	uint16_t tcp_chksum;        /* TCP Checksum */
	uint16_t tcp_urgptr;        /* TCP Urgent Pointer */
};
struct eth_ip_udp_hdr
{
	uint8_t eth_dst[6];         /* MAC Destination Address */
	uint8_t eth_src[6];         /* MAC Source Address */
	uint16_t eth_type;          /* Ethernet Type */
	uint8_t ip_ver_hdrlen;      /* Version and Header Length */
	uint8_t ip_dsfield;         /* Differentiated Services Field */
	uint16_t ip_len;            /* Total Length */
	uint16_t ip_id;             /* Identification */
	uint16_t ip_flag_frag;      /* Flags and Fragment offset */
	uint8_t ip_ttl;             /* Time to live */
	uint8_t ip_proto;           /* Protocol */
	uint16_t ip_chksum;         /* Header checksum */
	uint32_t ip_src;            /* IP Source Address */
	uint32_t ip_dst;            /* IP Destination Address */
	uint16_t udp_srcport;       /* UDP Source Port */
	uint16_t udp_dstport;       /* UDP Destination Port */
	uint16_t udp_len;           /* UDP Length */
	uint16_t udp_chksum;        /* UDP Checksum */
};

uint32_t myIP = 0;
int Data = 0;
double Bps_TX = 0;
double Bps_RX = 0;

void get_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct eth_ip_tcp_hdr *tcp = packet;//assume TCP packet
	struct eth_ip_udp_hdr *udp = packet;//assume UDP packet
	if (tcp->eth_type == 0x0008)//Internet Protocol version 4 (IPv4)
	{
		if (tcp->ip_proto == 0x06)//Transmission Control Protocol (TCP)
		{
			Data = (tcp->ip_len / 256 + (tcp->ip_len % 256) * 256) - (tcp->ip_ver_hdrlen & 0x0f) * 4 - (packet[46] / 16) * 4;//TCP data length, Big-endian to Little-endian
			if (myIP == *(uint32_t*)(packet + 26))//Upload traffic
			{
				Bps_TX += Data;
			}
			if (myIP == *(uint32_t*)(packet + 30))//Download traffic
			{
				Bps_RX += Data;
			}
		}
		if (udp->ip_proto == 0x11)//User Datagram Protocol (UDP)
		{
			Data = (udp->ip_len / 256 + (udp->ip_len % 256) * 256) - (udp->ip_ver_hdrlen & 0x0f) * 4 - 8;//UDP data length, Big-endian to Little-endian
			if (myIP == *(uint32_t*)(packet + 26))//Upload traffic
			{
				Bps_TX += Data;
			}
			if (myIP == *(uint32_t*)(packet + 30))//Download traffic
			{
				Bps_RX += Data;
			}
		}
	}
}

void create_db()
{
	int rc;
	sqlite3 *db;
	char *zErrMsg = 0;
	
	rc = sqlite3_open("/etc/NetworkTrafficMonitor.db", &db);//Open database. Create new if not exist.
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}
	
	rc = sqlite3_exec(db, "create table traffic(date text not null, sent integer not null, recv integer not null, primary key (date));", NULL, NULL, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	sqlite3_close(db);
	return;
}

void save_db(time_t *Today)
{
	int rc;
	sqlite3 *db;
	char *zErrMsg = 0;
	struct tm *tm_time_now;
	char sql[100];
	double Today_TX;
	double Today_RX;
	FILE *fileptr;
	
	create_db();
	
	fileptr = fopen("/etc/NetworkTrafficMonitor.txt", "r");
	fscanf(fileptr, "%f %f", &Today_TX, &Today_RX);
	fclose(fileptr);
	
	rc = sqlite3_open("/etc/NetworkTrafficMonitor.db", &db);//Open database. Create new if not exist.
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}
	
	tm_time_now = localtime(Today);
	sprintf(sql, "insert into traffic values (\"%d-%02d-%02d\", %.0f, %.0f);", tm_time_now->tm_year + 1900, tm_time_now->tm_mon + 1, tm_time_now->tm_mday, Today_TX, Today_RX);//GMT to localtime
	rc = sqlite3_exec(db, sql, NULL, NULL, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	sqlite3_close(db);
	return;
}

void show_db()
{
	sqlite3 *db;
	char *zErrMsg = 0;
	char **dbResult;
	int nRow = 0, nColumn = 0;
	int rc;
	int i, j;
	
	rc = sqlite3_open("/etc/NetworkTrafficMonitor.db", &db);//Open database. Create new if not exist.
	if (rc)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}
	rc = sqlite3_get_table(db, "select * from traffic;", &dbResult, &nRow, &nColumn, &zErrMsg);
	if (rc != SQLITE_OK)
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	for (i = 0; i <= nRow; ++i)
	{
		for (j = 0; j < nColumn; ++j)
		{
			printf("%s\t", dbResult[i * nColumn + j]);
		}
		printf("\n");
	}
	
	sqlite3_free_table(dbResult);
	sqlite3_close(db);
	return;

}

void set_Bps_0()
{
	double Today_TX = 0;
	double Today_RX = 0;
	time_t Today_Date = 0;
	FILE *fileptr;
	
	Today_Date = (time(NULL) + 28800) / 86400 * 86400;
	while (1)
	{
		sleep(1);
		printf("U:%.2fkB/s, D:%.2fkB/s\n", Bps_TX / 1024, Bps_RX / 1024);
		
		fileptr = fopen("/etc/NetworkTrafficMonitor.txt", "w+");
		fscanf(fileptr, "%f %f %ld\n", &Today_TX, &Today_RX, &Today_Date);
		fclose(fileptr);
		
		if (Today_Date < (time(NULL) + 28800) / 86400 * 86400)//reset when UTC+8 is at midnight instead of UTC
		{
			save_db(&Today_Date);
			Today_TX = 0;
			Today_RX = 0;
		}
		
		Today_TX += Bps_TX;
		Today_RX += Bps_RX;
		Today_Date = (time(NULL) + 28800) / 86400 * 86400;
		Bps_TX = 0;
		Bps_RX = 0;
		
		fileptr = fopen("/etc/NetworkTrafficMonitor.txt", "w");
		fprintf(fileptr, "%.0f %.0f %ld\n", Today_TX, Today_RX, Today_Date);
		fclose(fileptr);
	}
}

int main(int argc, char *argv[])
{
	pcap_t *handle;					/* Session handle */
	char *dev;						/* The device to sniff on */
	pcap_if_t *alldevs, *_alldevs;	/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program filtprog;	/* The compiled filter */
	char filter_exp[] = "ip";		/* The filter expression */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */
	struct pcap_pkthdr header;		/* The header that pcap gives us */
	const u_char *packet;			/* The actual packet */
	int ret = 0;
	int i = 1;
	pthread_t Bps_reset;
	
	/* Define the device */
	if (pcap_findalldevs(&alldevs, errbuf))
	{
		fprintf(stderr, "Couldn't find any device: %s\n", errbuf);
		return(2);
	}
	if (alldevs == NULL)
	{
		fprintf(stderr, "Couldn't find any device: %s\n", errbuf);
		return(2);
	}
	for (_alldevs = alldevs; _alldevs != NULL; ++i)//show all devices
	{
		printf("%d: %s\n", i, _alldevs->name);
		_alldevs = _alldevs->next;
	}
	printf("0: Show traffic database\n");
	
	while (1)//select device
	{
		i = 0;
		_alldevs = alldevs;
		printf("Please select:");
		scanf("%d", &i);
		if (i == 0)
		{
			show_db();
			return(0);
		}
		for (; i > 1 && _alldevs != NULL; --i)
		{
			_alldevs = _alldevs->next;
		}
		if (_alldevs == NULL)
		{
			fprintf(stderr, "wrong input!\n");
			continue;
		}
		dev = _alldevs->name;
		
		//get dev IP
		struct pcap_addr *dev_addr;
		for (dev_addr = _alldevs->addresses; dev_addr != NULL; dev_addr = dev_addr->next)
		{
			if (dev_addr->addr->sa_family == AF_INET)//IPv4 AF_INET sockets
			{
				//printf("address %x with netmask %x\n", ((struct sockaddr_in *)(dev_addr->addr))->sin_addr.s_addr, ((struct sockaddr_in *)(dev_addr->netmask))->sin_addr.s_addr);
				myIP = ((struct sockaddr_in *)(dev_addr->addr))->sin_addr.s_addr;
			}
		}
		break;
	}
	printf("%s:\n", dev);
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, 65535, 0, 0, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &filtprog, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &filtprog) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	/* Create pthread Bps_reset */
	ret = pthread_create(&Bps_reset, NULL, (void*)set_Bps_0, NULL);
	if (ret)
	{
		fprintf(stderr, "pthread_create Bps_reset error: %s\n", strerror(ret));
		return;
	}
	/* Grab packets */
	pcap_loop(handle, -1, get_packet, NULL);
	/* And close the session */
	pcap_close(handle);
	return(0);
}
