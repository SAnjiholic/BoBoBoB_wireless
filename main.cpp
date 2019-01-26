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
	struct probe_field *pf;

	const u_char *data;
	char * errbuf;
	int res;	
	int k_index = 0;
	int p_index = 0;

	map< string , struct display_field > airocrack;
	map< int , string > index;

	map< string , struct probe_field> probecrack;
	map< int , string > index2;

	vector<struct display_field > vt;
	vector<struct probe_field > pvt;

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

		if(bf->frame_field == 0x0080){
			fp = (struct fixed_parameters *) (data + rdt->len + sizeof(*bf));
			tp = (struct tagged_parameters *) (data + rdt->len + sizeof(*bf) + sizeof(*fp));
			string bssid = mac_to_str(bf->bssid);

			if (airocrack.find(bssid) == airocrack.end()){
				struct display_field tmp_df;
				vt.push_back(tmp_df);
				airocrack.insert(make_pair(bssid,vt.back()));
				index.insert(make_pair(k_index,bssid)); k_index++;
				auto df_point = airocrack.find(bssid);
				df_point->second.bssid = bssid;
				if ((fp->capabilities[0] & 0x10 )!= 0x10 ){ df_point->second.encript.append("OPEN");}
				else { df_point->second.encript = "WPA"; }
				int offset = 0;
				while (offset < (header->len - rdt->len + sizeof(*bf) + sizeof(*fp)) ){
					tp = (struct tagged_parameters *) (data + rdt->len + sizeof(*bf) + sizeof(*fp) + offset);

					if(tp->flag == 0 && tp->length != 0 && tp->data[0] > 0x29  && tp->data[0] < 0x5b ){
						string essid = ssid_to_str(tp->data,int(tp->length));
						df_point->second.essid = essid;
						offset += (int(tp->length) + 2 );
					}
					else if(tp->flag == 0x03){
						df_point->second.channel = tp->data[0];
						offset += 3;
					}
					else if(tp->flag == 0x30){
						df_point->second.encript = "WPA2";
						if (int(tp->data[int(tp->length)-3]) == 2) df_point->second.auth.append("PSK");
						if (int(tp->data[int(tp->length)-9]) == 4) df_point->second.cipher.append("CCMP");
						if (int(tp->data[int(tp->length)-9]) == 2) df_point->second.cipher.append("TKIP");
						offset += int(tp->length)+2;
					}
					else {
						offset += int(tp->length) +2;
					}
				}
				df_point->second.bssid = bssid;
				df_point->second.pwr = rdt->antenna_signal;
				df_point->second.beacon_count = 0;

			}
			else{
				airocrack.find(bssid)->second.beacon_count++;
			}
		}
		else if (bf->frame_field == 0x0040 || 0x0050 || 0x0840 || 0x0850){
			tp = (struct tagged_parameters *) (data + rdt->len + sizeof(*bf));
			string bssid = mac_to_str(bf->bssid);
			string station = "";
			if (bssid != "ff:ff:ff:ff:ff:ff" && airocrack.find(bssid) != airocrack.end()){
				struct probe_field tmp_pf;
				if(bf->frame_field== 0x0040){ 
					station = mac_to_str(bf->source_addr);
				}
				else if (bf->frame_field == 0x0050){
					station = mac_to_str(bf->destination_addr);
				}
				if(probecrack.find(station) == probecrack.end()){ 
					pvt.push_back(tmp_pf);
					probecrack.insert(make_pair(station,pvt.back()));
					auto probe_point = probecrack.find(station)->second;
					probe_point.bssid = bssid;
					probe_point.station = station;
					probe_point.pwr = rdt->antenna_signal;
					probe_point.lost = 0;
					probe_point.frame = 0;

					index2.insert(make_pair(p_index,station));
					p_index++;
				}
			}

		}

		system("clear");
		printf("%-18s %3s %7s %5s %3s %3s %6s %6s %6s %6s %10s \n","BSSID","PWR","Beacons","#Data","#/s","CH","MB","ENC","CIPHER","AUTH","ESSID");
		for (int a = 0; a < k_index; a++){
			auto beacon_point = airocrack.find(index.find(a)->second)->second;
			if(beacon_point.essid != ""
					&& beacon_point.essid[0] >0x29 
					&& int(beacon_point.beacon_count) > 0){

				printf("%-18s %3d %7d %5s %3s %3d %6s %6s %6s %6s %10s \n",
						beacon_point.bssid.c_str(),
						int(beacon_point.pwr),
						int(beacon_point.beacon_count),
						"", //#data
						"", //D/S
						int(beacon_point.channel),
						"", //MB
						beacon_point.encript.c_str(),
						beacon_point.cipher.c_str(),
						beacon_point.auth.c_str(),
						beacon_point.essid.c_str());
			}
		}
		printf("\n\n%-18s %-18s %3s %7s %5s %5s %10s \n","BSSID","STATION","PWR","RATE","Lost","Frames","Probe");
		for(int b = 0; b < p_index; b++){
			auto probe_point = probecrack.find(index2.find(b)->second)->second;
			if(probe_point.station != ""){
				printf("%-18s %-18s %5d %7s %5d %5d %10s \n",
						probe_point.bssid.c_str(),
						probe_point.station.c_str(),
						int(probe_point.pwr),
						"0", //rate
						0, //rost
						0, //frames
						"Probe"); //probe
			}
		}
		usleep(50000);
	}
}
