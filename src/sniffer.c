#include <linux/if_ether.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>            //For standard things
#include <stdlib.h>           //malloc
#include <string.h>           //strlen

#include <netinet/ip_icmp.h>  //Provides declarations for icmp header
#include <netinet/udp.h>      //Provides declarations for udp header
#include <netinet/tcp.h>      //Provides declarations for tcp header
#include <netinet/ip.h>       //Provides declarations for ip header
#include <netinet/if_ether.h> //For ETH_P_ALL
#include <net/ethernet.h>     //For ether_header
#include <strings.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define LOGFILE              "log.txt"
#define RECV_BUF_SIZE        65536

static int debug_mode      = 0;
static int dump_flag       = 0;
static int tcp             = 0;
static int udp             = 0;
static int icmp            = 0;
static int l2tp            = 0;
static int igmp            = 0;
static int others_protocol = 0;
static int packet_count    = 0;

FILE      *logfile;
char      *logfilename     = LOGFILE;

struct recv_packet {
        uint64_t     num;
        uint32_t     len;
        uint8_t     *buf;
};

void process_packet(struct recv_packet *);
void print_ip_header(struct recv_packet *);
void print_tcp_packet(struct recv_packet *);
void print_udp_packet(struct recv_packet *);
void print_icmp_packet(struct recv_packet *);
void print_dump(FILE *, unsigned char *, int);
void print_ethernet_header(struct recv_packet *);
void parse_ip_header(struct recv_packet *);

struct dump_data_info {
        char        *label;
        char        *start;
        size_t       size;
};

struct dump_data_info_pool {
        struct dump_data_info       *data;
        struct dump_data_info_pool  *next;
};
struct dump_data_info_pool *pool = NULL;

int data_pool_destroy(struct dump_data_info_pool **head) 
{
        struct dump_data_info_pool *current = *head;

        if (current == NULL) {
                return 0;
        } else {
                while (current->next != NULL) {
                        *head = current->next;
                        free(current->data->label);
                        free(current->data);
                        free(current);
                        current = *head;
                }
        }

        if (current) {
                free(current->data->label);
                free(current->data);
                free(current);
                current = *head;
        }

        *head = NULL;

        return 0;
}

int append_data_to_pool(struct dump_data_info_pool **head,
                        struct dump_data_info       *data) 
{
	struct dump_data_info_pool *current = *head;
	struct dump_data_info_pool *new =
		malloc(sizeof(struct dump_data_info_pool));
	if (!new)
		return 1;

	new->next = NULL;
        new->data = data;

	if (current == NULL) {
		*head = new;
	} else {
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = new;
	}

	return 0;
}

void print_pool(struct dump_data_info_pool **head)
{
	struct dump_data_info_pool *current = *head;

	if (current == NULL)
		return;

	while (current != NULL) {
		fprintf(logfile, "%s\n", current->data->label);
		print_dump(logfile, (unsigned char *)current->data->start,
			   current->data->size);
		if (debug_mode)
			printf("DEBUG_MSG pritn pool %s! \n",
			       current->data->label);
		current = current->next;
	}
}

int get_mem(size_t size, void *ptr)
{
	void *pp;

	pp = malloc(size);
	if (!pp)
		return 1;
	memcpy(ptr, &pp, sizeof(pp));
	return 0;
}

int new_dump_data(const char *label, void *start, size_t size)
{
        int ret = 0;
        struct dump_data_info *ddi = NULL;

        ret = get_mem(sizeof(struct dump_data_info), &ddi);
        if (ret)
                return ret;
        memset(ddi, 0, sizeof(struct dump_data_info));

	ret = get_mem(strlen(label) + 1, &ddi->label);
	if (ret) {
		free(ddi);
		return ret;
	}
	strcpy(ddi->label, label);
	ddi->start = start;
	ddi->size  = size;

	if (append_data_to_pool(&pool, ddi)) 
                perror("malloc error new data dump sturct %p \n");

        return ret;
}

void usage(FILE *file, char *progname)
{
	fprintf(file, "Usage: %s [-d add dump data] [-l log file] [-h]\n", progname);
	fprintf(file, "\nOptions:\n");
	fprintf(file, "  -d     Show data dump (hex/ascii)\n");
	fprintf(file, "  -l     Set the file name for logging\n");
	fprintf(file, "         default ./log.txt\n");
	fprintf(file, "  -h     Print this help message\n");
}


void process_packet(struct recv_packet *pkt)
{
	struct ether_header *eth = (struct ether_header *)pkt->buf;
	pkt->num = ++packet_count;

	fprintf(logfile, "########################################################################\n");
	fprintf(logfile, "Packet #%lu (%d bytes read)\n", pkt->num, pkt->len);

        print_ethernet_header(pkt);

	switch (ntohs(eth->ether_type)) {
	case ETH_P_IP:
		parse_ip_header(pkt);
		break;

	case ETH_P_ARP:
	case ETH_P_RARP:
		break;

	case ETH_P_X25:
		break;

	default:
		break;
	}

        if (dump_flag) {
                fprintf(logfile, "                        DATA Dump           "
                                  "              ");
                fprintf(logfile, "\n");
                print_pool(&pool);
                fprintf(logfile, "\n");

		/* Destroy pool after print all dump data */
		data_pool_destroy(&pool);
		if (debug_mode) {
			if (!pool)
				printf("DEBUG_MSG destroy pool OK! \n");
			else
				printf("DEBUG_MSG destroy pool FAIL! \n");
		}
	}
}

void parse_ip_header(struct recv_packet *pkt)
{
	struct ip *ip = (struct ip *)(pkt->buf + sizeof(struct ether_header));

	print_ip_header(pkt);

	/* Check the Protocol */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		++tcp;
		print_tcp_packet(pkt);
		break;

	case IPPROTO_UDP:
		++udp;
		print_udp_packet(pkt);
		break;

	case IPPROTO_ICMP:
		++icmp;
		print_icmp_packet(pkt);
		break;

	case IPPROTO_IGMP:
		++igmp;
		break;

	case IPPROTO_L2TP:
		++l2tp;
		break;

	default: /* Some Other Protocol  */
		++others_protocol;
		break;
	}

	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   L2TP : %d   Others : %d   Total : %d\r",
	       tcp, udp, icmp, igmp, l2tp, others_protocol, packet_count);
}

void print_ethernet_header(struct recv_packet *pkt)
{
	struct ether_header *eth = (struct ether_header *)pkt->buf;

	fprintf(logfile, "\n");
	fprintf(logfile, "Ethernet Header\n");
	fprintf(logfile,
		"   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	fprintf(logfile,
		"   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	fprintf(logfile, "   |-Protocol            : 0x%.4X \n",
		ntohs(eth->ether_type));
}

void print_ip_header(struct recv_packet *pkt)
{
	struct ip *ip   = (struct ip *)(pkt->buf + sizeof(struct ether_header));
	ushort iphdrlen = ip->ip_hl * 4;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, "   |-IP Version        : %d\n", (uint)ip->ip_v);
	fprintf(logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",
		(uint)ip->ip_hl, ((uint)(ip->ip_hl)) * 4);
	fprintf(logfile, "   |-Type Of Service   : %d\n", (uint)ip->ip_tos);
	fprintf(logfile, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
		ntohs(ip->ip_len));
	fprintf(logfile, "   |-Identification    : %d\n", ntohs(ip->ip_id));
	//fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(uint)iphdr->ip_reserved_zero);
	//fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(uint)iphdr->ip_dont_fragment);
	//fprintf(logfile , "   |-More Fragment Field   : %d\n",(uint)iphdr->ip_more_fragment);
	fprintf(logfile, "   |-TTL      : %d\n", (uint)ip->ip_ttl);
	fprintf(logfile, "   |-Protocol : %d\n", (uint)ip->ip_p);
	fprintf(logfile, "   |-Checksum : %d\n", ntohs(ip->ip_sum));
	fprintf(logfile, "   |-Source IP        : %s\n",
		inet_ntoa(ip->ip_src));
	fprintf(logfile, "   |-Destination IP   : %s\n",
		inet_ntoa(ip->ip_dst));

	if (dump_flag) {
                new_dump_data("IP Header", (void *)ip, iphdrlen);
        }
}

void print_tcp_packet(struct recv_packet *pkt)
{
	struct ip *ip   = (struct ip *)(pkt->buf + sizeof(struct ether_header));
	ushort iphdrlen = ip->ip_hl * 4;

	struct tcphdr *tcph =
		(struct tcphdr *)(pkt->buf + sizeof(struct ether_header) +
				  iphdrlen);

	int header_size =
		sizeof(struct ether_header) + iphdrlen + tcph->th_off * 4;

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, "   |-Source Port      : %u\n", ntohs(tcph->th_sport));
	fprintf(logfile, "   |-Destination Port : %u\n", ntohs(tcph->th_dport));
	fprintf(logfile, "   |-Sequence Number    : %u\n", ntohl(tcph->th_seq));
	fprintf(logfile, "   |-Acknowledge Number : %u\n", ntohl(tcph->th_ack));
	fprintf(logfile, "   |-Header Length      : %d DWORDS or %d BYTES\n",
		(uint)tcph->th_off, (uint)tcph->th_off * 4);
	/* 
         * FIXME: add cwr/ecn flag support. It's not define on LINUX in
         * netinet/tcp.h, only linux/tcp.h for LINUX and netinet/tcp.h for BSD.
         */
	/* fprintf(logfile , "   |-CWR Flag : %d\n",(uint)tcph->cwr); */
	/* fprintf(logfile , "   |-ECN Flag : %d\n",(uint)tcph->ece); */
	fprintf(logfile, "   |-Urgent Flag            : %d\n",
		(tcph->th_flags & TH_URG) ? 1 : 0);
	fprintf(logfile, "   |-Acknowledgement Flag : %d\n",
		(tcph->th_flags & TH_ACK) ? 1 : 0);
	fprintf(logfile, "   |-Push Flag            : %d\n",
		(tcph->th_flags & TH_PUSH) ? 1 : 0);
	fprintf(logfile, "   |-Reset Flag           : %d\n",
		(tcph->th_flags & TH_RST) ? 1 : 0);
	fprintf(logfile, "   |-Synchronise Flag     : %d\n",
		(tcph->th_flags & TH_SYN) ? 1 : 0);
	fprintf(logfile, "   |-Finish Flag          : %d\n",
		(tcph->th_flags & TH_FIN) ? 1 : 0);
	fprintf(logfile, "   |-Window         : %d\n", ntohs(tcph->th_win));
	fprintf(logfile, "   |-Checksum       : %d\n", ntohs(tcph->th_sum));
	fprintf(logfile, "   |-Urgent Pointer : %d\n", tcph->th_urp);
	fprintf(logfile, "\n");

        if (dump_flag) {
                new_dump_data("TCP Header", (void *)tcph, tcph->th_off * 4);
                new_dump_data("Data Payload", (void *)pkt->buf + header_size,
                              pkt->len - header_size);
        }
}


void print_udp_packet(struct recv_packet *pkt)
{
	ushort iphdrlen;

	struct ip *ip = (struct ip *)(pkt->buf + sizeof(struct ether_header));
	iphdrlen = ip->ip_hl * 4;

	struct udphdr *udph = (struct udphdr *)(pkt->buf + iphdrlen +
						sizeof(struct ether_header));

	int header_size =
		sizeof(struct ether_header) + iphdrlen + sizeof(struct udphdr);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, "   |-Source Port      : %d\n", ntohs(udph->uh_sport));
	fprintf(logfile, "   |-Destination Port : %d\n", ntohs(udph->uh_ulen));
	fprintf(logfile, "   |-UDP Length       : %d\n", ntohs(udph->uh_ulen));
	fprintf(logfile, "   |-UDP Checksum     : %d\n", ntohs(udph->uh_sum));

	fprintf(logfile, "\n");

        if (dump_flag) {
                new_dump_data("UDP Header", (void *)udph,
                              sizeof(struct udphdr));
                new_dump_data("Data Payload", (void *)pkt->buf + header_size,
                              pkt->len - header_size);
        }
}

void print_icmp_packet(struct recv_packet *pkt)
{
	ushort iphdrlen;

	struct ip *ip = (struct ip *)(pkt->buf + sizeof(struct ether_header));
	iphdrlen = ip->ip_hl * 4;

	struct icmphdr *icmph =
		(struct icmphdr *)(pkt->buf + sizeof(struct ether_header) +
				   iphdrlen);

        /* FIXME: What size icmphdr on BSD? Test it. */
        int header_size =
            sizeof(struct ether_header) + iphdrlen + sizeof(struct icmphdr);

        fprintf(logfile, "\n");

        fprintf(logfile, "ICMP Header\n");
        fprintf(logfile, "   |-Type : %d", (uint)(icmph->type));

        if ((uint)(icmph->type) == 11) {
                fprintf(logfile, "  (TTL Expired)\n");
        } else if ((uint)(icmph->type) == ICMP_ECHOREPLY) {
                fprintf(logfile, "  (ICMP Echo Reply)\n");
        }

        fprintf(logfile, "   |-Code : %d\n", (uint)(icmph->code));
        fprintf(logfile, "   |-Checksum : %d\n", ntohs(icmph->checksum));
        /* FIXME: id, sequence in BSD not tested! Only Linux */
        fprintf(logfile, "   |-ID       : %d\n", ntohs(icmph->un.echo.id));
        fprintf(logfile, "   |-Sequence : %d\n",
                ntohs(icmph->un.echo.sequence));
        fprintf(logfile, "\n");

        if (dump_flag) {
                new_dump_data("ICMP Header", (void *)icmph,
                              sizeof(struct icmphdr));
                new_dump_data("Data Payload", (void *)pkt->buf + header_size,
                              pkt->len - header_size);
        }
}

/* Maybe refactor this code like on ТНЕ ART OF EXPLOITATION (page 225) */
void print_dump(FILE *file, unsigned char *data, int size)
{
	int i, j;
	for (i = 0; i < size; i++) {
		/* if one line of hex printing is complete... */
		if (i != 0 && i % 16 == 0) {
			fprintf(file, "         ");
			for (j = i - 16; j < i; j++) {
				/* if its a number or alphabet */
				if (data[j] >= 32 && data[j] <= 128)
					fprintf(file, "%c",
						(unsigned char)data[j]);
				else
					/* otherwise print a dot */
					fprintf(file, ".");
			}
			fprintf(file, "\n");
		}

		if (i % 16 == 0)
			fprintf(file, "   ");
		fprintf(file, " %02X", (uint)data[i]);

		/* print the last spaces */
		if (i == size - 1) {
			for (j = 0; j < 15 - i % 16; j++) {
				/* extra spaces */
				fprintf(file, "   ");
			}

			fprintf(file, "         ");

			for (j = i - i % 16; j <= i; j++) {
				if (data[j] >= 32 && data[j] <= 128) {
					fprintf(file, "%c",
						(unsigned char)data[j]);
				} else {
					fprintf(file, ".");
				}
			}

			fprintf(file, "\n");
		}
	}
}

int main(int argc, char *argv[])
{
	int                     rc, saddr_size, nread;
        int                     ret = EXIT_SUCCESS;
	struct sockaddr         saddr;
	struct recv_packet      packet;
	unsigned char          *recv_buf = NULL;


	while ((rc = getopt(argc, argv, "dl:h")) != -1) {
		switch (rc) {
		case 'd':
			dump_flag = 1;
			break;
		case 'l':
			logfilename = optarg;
			break;
		case 'h':
			usage(stdout, argv[0]);
			goto exit;
			break;
		case '?':
		default:
			usage(stderr, argv[0]);
			ret = EXIT_FAILURE;
			goto exit;
			break;
		}
	}

	logfile = fopen(logfilename, "w");
	if (logfile == NULL)
		perror("Unable to create log.txt file.");
	else
		printf("Log filename: %s\n", logfilename);

	if (dump_flag)
		printf("Dump data enable: \n");
	else
		printf("Dump data disable: \n");

	printf("Starting...\n");

	int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	/* setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 ); */

	if (sock_raw < 0) {
		perror("Socket Error");
		return EXIT_FAILURE;
	}

	bzero(&packet, sizeof(struct recv_packet));
	recv_buf = (unsigned char *)malloc(65536); 

	for (;;) {
		saddr_size = sizeof saddr;
		/* Receive a packet */
		nread = recvfrom(sock_raw, recv_buf, 65536, 0, &saddr,
				 (socklen_t *)&saddr_size);
		if (nread < 0) {
			printf("Recvfrom error , failed to get packets\n");
			return 1;
		}
		/* Now process the packet */
                packet.buf = recv_buf;
                packet.len = nread;
                process_packet(&packet);
        }

        close(sock_raw);
        printf("Finished");
exit:
        if (logfile)
                fclose(logfile);
        if (pool) 
                data_pool_destroy(&pool);
	return ret;
}
