#ifndef MYHEADER_H
#define MYHEADER_H

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct ethheader {
    u_char  ether_dhost[6]; // 목적지 MAC (6바이트) 
    u_char  ether_shost[6]; // 출발지 MAC (6바이트)
    u_short ether_type;     // 프로토콜 타입
};

struct ipheader {
    u_char  ver_ihl;         // 버전 + 헤더 길이
    u_char  tos;             // 서비스 유형
    u_short tlen;            // 전체 패킷 길이 (헤더 + 데이터)
    u_short id;              // 패킷 식별자
    u_short flags_offset;    // 플래그 + 프래그먼트 오프셋
    u_char  ttl;             // TTL
    u_char  proto;           // 상위 프로토콜 
    u_short crc;             // 헤더 체크섬
    struct  in_addr src_ip;  // 출발지 IP
    struct  in_addr dst_ip;  // 목적지 IP
};

struct tcpheader {
    u_short src_port;        // 출발지 포트
    u_short dst_port;        // 목적지 포트
    u_int   seq_num;         // 순서 번호
    u_int   ack_num;         // 확인 응답 번호
    u_char  offset_reserved; // 데이터 오프셋 + 예약 필드
    u_char  flags;           // 플래그 비트 
    u_short win_size;        // 윈도우 크기
    u_short checksum;        // 체크섬
    u_short urg_ptr;         // 긴급 포인터
};

#endif
