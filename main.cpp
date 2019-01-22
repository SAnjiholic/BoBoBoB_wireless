#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <thread>
#include <pcap.h>
#include <map>
#include "struct.h"

using namespace std;

string mac_to_str(uint8_t mac[]){
	char test[25];
	sprintf(test,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return test;
}
string ssid_to_str(uint8_t data[],int length){
	string ret = "";
	char tmp[32] = {0,};
	if(length > 32 ) length = 30;
	copy(data,data+length,tmp);
	ret.append(tmp);
	memset(tmp,0,length+1);
	return ret;	
}

void start_perl(){
	system("perl ./1.pl &");
}

int main(int argv, char **argc){
	struct pcap_pkthdr *header;
	struct radiotap_header *rdt;
	struct beacon_frame *bf;
	struct fixed_parameters *fp;
	struct tagged_parameters *tp;
	const u_char *data;
	char * errbuf;
	int res;	
	int k_index = 0;

	map< string , struct display_field > airocrack;
	map< int , string > index;
	vector<struct display_field > vt;
	pcap_t *handler = pcap_create(argc[1], errbuf);
	if (handler == NULL) exit(-1);
	if(pcap_set_rfmon(handler,13)==0 ) printf("monitor mode enabled\n");

	pcap_set_snaplen(handler, 2048);
	pcap_set_promisc(handler, 0);
	pcap_set_timeout(handler, 512);
	pcap_activate(handler);
	//	thread t1(start_perl);

	while((res = pcap_next_ex(handler, &header, &data)) >=0){
		if(res == 0) continue;
		rdt = (struct radiotap_header *) data;
		bf = (struct beacon_frame *) (data + rdt->len);
		fp = (struct fixed_parameters *) (data + rdt->len + sizeof(*bf));
		tp = (struct tagged_parameters *) (data + rdt->len + sizeof(*bf) + sizeof(*fp));

		if(bf->frame_field == 0x0080){
			string bssid = mac_to_str(bf->bssid);

			if (airocrack.find(bssid) == airocrack.end()){
				struct display_field tmp_df;
				vt.push_back(tmp_df);
				airocrack.insert(make_pair(bssid,vt.back()));
				index.insert(make_pair(k_index,bssid)); k_index++;
				airocrack.find(bssid)->second.bssid = bssid;
				if ((fp->capabilities[0] & 0x10 )!= 0x10 ){ airocrack.find(bssid)->second.encript.append("OPEN");}
				else { airocrack.find(bssid)->second.encript = "WPA"; }
				int offset = 0;
				while (offset < (header->len - rdt->len + sizeof(*bf) + sizeof(*fp)) ){
					tp = (struct tagged_parameters *) (data + rdt->len + sizeof(*bf) + sizeof(*fp) + offset);

					if(tp->flag == 0 && tp->length != 0 && tp->data[0] > 0x29  && tp->data[0] < 0x5b ){
						string essid = ssid_to_str(tp->data,int(tp->length));
						airocrack.find(bssid)->second.essid = essid;
						offset += (int(tp->length) + 2 );
					}
					else if(tp->flag == 0x03){
						airocrack.find(bssid)->second.channel = tp->data[0];
						offset += 3;
					}
					else if(tp->flag == 0x30){
						airocrack.find(bssid)->second.encript = "WPA2";
						if (int(tp->data[int(tp->length)-3]) == 2) airocrack.find(bssid)->second.auth.append("PSK");
						if (int(tp->data[int(tp->length)-9]) == 4) airocrack.find(bssid)->second.cipher.append("CCMP");
						if (int(tp->data[int(tp->length)-9]) == 2) airocrack.find(bssid)->second.cipher.append("TKIP");
						offset += int(tp->length)+2;
					}
					else {
						offset += int(tp->length) +2;
					}
				}
				airocrack.find(bssid)->second.bssid = bssid;
				airocrack.find(bssid)->second.pwr = rdt->antenna_signal;
				airocrack.find(bssid)->second.beacon_count = 0;

			}
			else{
				airocrack.find(bssid)->second.beacon_count++;
			}
		}
		system("clear");
		printf("%-18s %3s %7s %5s %3s %3s %6s %6s %6s %6s %10s \n","BSSID","PWR","Beacons","#Data","#/s","CH","MB","ENC","CIPHER","AUTH","ESSID");
		for (int a = 0; a < k_index; a++){
			if(airocrack.find(index.find(a)->second)->second.essid != "" && airocrack.find(index.find(a)->second)->second.essid[0] >0x29 && int(airocrack.find(index.find(a)->second)->second.beacon_count) > 0){
				printf("%-18s %3d %7d %5s %3s %3d %6s %6s %6s %6s %10s \n",airocrack.find(index.find(a)->second)->second.bssid.c_str(), int(airocrack.find(index.find(a)->second)->second.pwr), int(airocrack.find(index.find(a)->second)->second.beacon_count),"","",int(airocrack.find(index.find(a)->second)->second.channel),"",airocrack.find(index.find(a)->second)->second.encript.c_str(),airocrack.find(index.find(a)->second)->second.cipher.c_str(),airocrack.find(index.find(a)->second)->second.auth.c_str(),airocrack.find(index.find(a)->second)->second.essid.c_str());
			}
		}
		usleep(50000);
	}
}
