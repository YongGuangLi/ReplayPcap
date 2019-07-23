#include "dissectpacket.h"



QString GBK2Unicode(QByteArray inStr)
{
    QTextCodec* gbk = QTextCodec::codecForName("gbk");
    return gbk->toUnicode(inStr);
}

DissectPacket::DissectPacket(QObject *parent) :
    QObject(parent)
{
    iCnt = 0;

    init_process_policies();
    epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);
}




void DissectPacket::tryDissect(const pcap_pkthdr *pkthdr, const u_char *packet)
{
    frame_data  *fdata = NULL;
    epan_dissect_t  *edt = NULL;
    struct pcap_pkthdr *pheader = new struct pcap_pkthdr;
    memcpy(pheader, pkthdr, sizeof(struct pcap_pkthdr));
    struct wtap_pkthdr *phdr = new struct wtap_pkthdr;
    pseudo_header.eth.fcs_len = -1;

    fdata = (frame_data*)g_new(frame_data, 1);

    memset(fdata, 0, sizeof(frame_data));
    fdata->pfd  = NULL;
    fdata->num = 1;
    //fdata->interface_id = 0;
    fdata->pkt_len  = pkthdr->len;
    fdata->cap_len  = pkthdr->caplen;
    fdata->cum_bytes = 0;
    fdata->file_off = 0;
    fdata->subnum = 0;
    fdata->lnk_t = 0; //WTAP_ENCAP_ETHERNET
    fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII;
    fdata->flags.visited = 0;
    fdata->flags.marked = 0;
    fdata->flags.ref_time = 0;
    fdata->color_filter = NULL;
    fdata->abs_ts.secs = 0;
    fdata->abs_ts.nsecs = 0;
    //fdata->opt_comment = NULL;

    edt = epan_dissect_new(NULL, TRUE, TRUE);
//   printf("TryDissect-epan_dissect_new--------------------*****-------------edt:%p\n",edt);
    epan_dissect_run(edt, 0,  &phdr, packet, fdata, NULL);

    /*
    ++iCnt;

    struct ether_header *ethernet = (struct ether_header *)(packet);
    int etherType = ntohs(ethernet->ether_type);
    switch(etherType)
    {
    case ETHERTYPE_IP:
        dissectIp(pkthdr, packet, ETHER_HDR_LEN);
        break;
    case ETHERTYPE_VLAN:
        if(packet[ETHER_HDR_LEN + 3] == 0x00 && packet[ETHER_HDR_LEN + 2] == 0x08)
            dissectIp(pkthdr, packet, ETHER_HDR_LEN + 4);
        break;
    case ETHERTYPE_ARP:
        break;
    default:
        break;
    }
    */
}




void DissectPacket::dissectIp(const pcap_pkthdr *pkthdr, const u_char *packet, int offset)
{
    iphdr = (struct ip *)(packet + offset);

    //DEBUG(inet_ntoa(iphdr->ip_src)<<inet_ntoa(iphdr->ip_dst)<<iphdr->ip_hl;

    int size_ip = iphdr->ip_hl * 4;
    if (size_ip < IP_HEADER_LEN)
        return;

    int protoType = iphdr->ip_p;
    switch(protoType)
    {
    case IPPROTO_TCP:
        dissectTcp(pkthdr, packet, offset + size_ip);
        break;
    case IPPROTO_UDP:
        break;
    case IPPROTO_ICMP:
        break;
    default:
        break;
    }
}



void DissectPacket::dissectTcp(const pcap_pkthdr *pkthdr, const u_char *packet, int offset)
{
    tcp = (struct tcphdr *)(packet + offset);

    int size_tcp = tcp->doff * 4;

    if(pkthdr->len <= offset + size_tcp)
        return;



    QByteArray body((char *)packet + offset + size_tcp, pkthdr->len - offset - size_tcp);
    if(body.split(0x00).size() == body.length() + 1)                                         //除去确认帧，数据段全是0x00
        return;

    tcpDate = body;
}

QByteArray DissectPacket::getTcpData()
{
    return tcpDate;
}

