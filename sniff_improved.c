#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"  // 사용자 정의 헤더 파일 포함합니다.


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷인지 확인합니다. (Ethernet 타입이 0x0800이면 IP 패킷임을 알 수 있습니다.)
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("\n---------------- Packet Capture ----------------\n");
        printf("       From: %s\n", inet_ntoa(ip->src_ip));
        printf("         To: %s\n", inet_ntoa(ip->dst_ip));

        // 상위 프로토콜을 확인합니다
        switch (ip->proto) {
            case IPPROTO_TCP: {
                printf("   Protocol: TCP\n");

                // TCP 헤더 가져옵니다
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ((ip->ver_ihl & 0x0F) * 4));

                printf("   SRC PORT: %d, DST PORT: %d\n", ntohs(tcp->src_port), ntohs(tcp->dst_port));

                // TCP 페이로드를 추출합니다 (가능한 경우에만)
                int ip_header_len = (ip->ver_ihl & 0x0F) * 4;
                int tcp_header_len = ((tcp->offset_reserved >> 4) & 0x0F) * 4;
                int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
                int payload_size = header->caplen - payload_offset;

                if (payload_size > 0) {
                    printf("   Message: ");
                    for (int i = 0; i < payload_size; i++) {
                        printf("%c", packet[payload_offset + i]);
                    }
                    printf("\n");
                }
                break;
            }
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                break;
            case IPPROTO_ICMP:
                printf("   Protocol: ICMP\n");
                break;
            default:
                printf("   Protocol: Others\n");
                break;
        }
        printf("-----------------------------------------------\n");
    }
}


int main() {
    pcap_t *handle;           // 패킷 캡처 핸들러
    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 버퍼
    struct bpf_program fp;    // BPF 필터 구조체
    char filter_exp[] = "tcp"; // 캡처할 패킷 필터
    bpf_u_int32 net;          // 네트워크 주소

    // 네트워크 인터페이스를 설정합니다.
    char *dev = "enp0s3";

    // 네트워크 인터페이스 엽니다.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // 필터를 컴파일하고 적용시킵니다.
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Listening on %s...\n", dev);

    // 패킷 캡처를 시작합니다 (-1은 무한 루프를 적용시킵니다.)
    pcap_loop(handle, -1, got_packet, NULL);

    // 캡처 종료 후 핸들을 닫습니다.
    pcap_close(handle);
    return 0;
}
