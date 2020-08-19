#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnet.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char* host_url;
int drop_pkt = 0;

void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;
	unsigned char *temp_data;

	struct libnet_ipv4_hdr *ip_hdr;
	//안에 struct in_addr ip_src, ip_dst가 있음.

	struct libnet_tcp_hdr *tcp_hdr;
	//안에 uint16_t th_sport, th_dport가 있음

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		/*printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
		*/
	}
/*
	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);

	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
*/
	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		//printf("payload_len=%d ", ret);
		//dump(data, ret);

		int k = sizeof(struct libnet_ipv4_hdr)+sizeof(struct libnet_tcp_hdr);

		//printf("ret int : %d \n", ret);
		//printf("ret-k   int : %d \n", ret-k);

		//IP - TCP - HTTP
		ip_hdr = (struct libnet_ipv4_hdr*)data;
		data += sizeof(struct libnet_ipv4_hdr);
		tcp_hdr = (struct libnet_tcp_hdr*)data;
		data += sizeof(struct libnet_tcp_hdr);

		char temp_char[100]; //url을 저장하기 위해서 임시로 생성
		int temp_loc = 0; //url의 저장 위치를 위해 선언
		int temp_size = 0; //url의 길이를 알기 위해 선언
		int exitOuterLoop = 0; //이중 포문을 빠져나오기 위해 선언

		if(ip_hdr->ip_p ==6 && ntohs(tcp_hdr->th_dport)==80){	//http 패킷인지 파악하기 위한 조건		
			printf ("------------------------HTTP PACKET---------------------\n");
			
			if( (data[0]=='G'&&data[1]=='E'&&data[2]=='T') || (data[0]=='P'&&data[1]=='O'&&data[2]=='S'&&data[3]=='T') ){	//GET or POST
				for(int i  = 4; ; i++){			//GET, POST 이후의 부분에 적용하기 위해 i  = 4 
					if(data[i]=='H'&&  data[i+1]=='o'&&  data[i+2]=='s'&&  data[i+3]=='t'){	  //Host URL 이 나오는 부분 찾음
						printf("Host URL :");
						for(int k = 6; k<50 ; k++){
							printf("%c", data[i+k]);
							temp_char[temp_loc++] = data[i+k]; //Host URL을 temp_char에 복사
							temp_size++;  //Host URL의 길이를 저장하기 위함
							if(data[i+k+1]=='U'&&  data[i+k+2]=='s'&&  data[i+k+3]=='e'&&  data[i+k+4]=='r'){ //Host URL의 끝부분 찾음
								exitOuterLoop = 1;
								break;
							}
						}
					}
					if(exitOuterLoop == 1)
						break;
				}

				for(int i = 0; i < temp_size; i++){ //Host URL의 길이만큼을, 함수 실행시 입력받았던 url과 비교
					if(temp_char[i] == host_url[i])
						drop_pkt = 1; //Packet Drop을 위한 변수 조정
					else
						break;
				}
			}

		}
	}
	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");

	if(drop_pkt == 1){
		printf("Packet DROPPED ! \n");
		drop_pkt = 0; //reset drop_pkt
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	host_url = argv[1];

	if(argc != 2){
		usage();
		return -1;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}

