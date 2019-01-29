#include "airodump.h"
#include <pcap.h>
#include <iostream>
using namespace std;

class Capture : public Save_data{
	private: 
		struct pcap_pkthdr *header;
		struct radiotap_header *rdt;
		pcap_t *handle;
		Beacon *beacon;
		Probe *probe;
		const u_char *data;
		char *errbuf;
		int pcap_check;
		int typecheck(const u_char *data);
		void parsing_beacon(const u_char *data, int length);
		void parsing_probe(const u_char *data);

	public:
		Capture();
		Capture(char *dev);
		~Capture();
		void display();
		void start();
		string char_to_string(u_int8_t mac[]);
		string ssid_to_str(uint8_t data[],int length);
};		


Capture::Capture(char *dev){
	beacon = new(Beacon);
	probe = new(Probe);
	//save_data = new(Save_data);

	handle = pcap_create(dev,errbuf);
	if(handle == NULL) exit(-1);
	if(pcap_set_rfmon(handle,1) == 0 ) cout << "monitor mode enabled" << endl;
	pcap_set_snaplen(handle,2048);
	pcap_set_promisc(handle,0);
	pcap_set_timeout(handle,512);
	pcap_activate(handle);
}


void Capture::start(){
	while ((pcap_check = pcap_next_ex(handle,&header,&data)) >= 0 ){
		if(pcap_check == 0) continue;
		//rdt = (struct radiotap_header *) data;
		int type = typecheck(data);

		switch(type) {
			case 1:{  	// beacon
					   Capture::parsing_beacon(data,header->len);
				   }

			case 2:{		// probe
					   Capture::parsing_probe(data);
					   break;
				   }
			case 3: {	// Data
						break;
					}
		}
	}
}
void Capture::parsing_probe(const u_char *data){
	probe->rh = (struct radiotap_header *) data;
	probe->pf = (struct probe_frame *) (data + probe->rh->len);
	probe->fixed = (struct fixed_parameters *) (data + probe->rh->len + 24);
	probe->tag = (struct tagged_parameters *) (data + probe->rh->len + 32);
	string bssid = char_to_string(probe->pf->bssid);
	string station = "";

	if (bssid != "ff:ff:ff:ff:ff:ff" && this->bmap.find(bssid) != this->bmap.end()){
		struct probe_field tmp_pf;
		//						   probe->pd = &tmp_pf;
		if(probe->pf->frame_field == 0x0040){
			station = char_to_string(probe->pf->source_addr);
		}
		else if (probe->pf->frame_field == 0x0050){
			station = char_to_string(probe->pf->destination_addr);
		}
		if(this->pmap.find(station) == this->pmap.end()){
			this->pv.push_back(tmp_pf);

			this->pmap_p = this->p_mapping(station);
			this->pmap_p->second.bssid = bssid;
			this->pmap_p->second.station = station;
			this->pmap_p->second.pwr = probe->rh->antenna_signal;
			this->pmap_p->second.lost = 0;
			this->pmap_p->second.frame = 0;
		}
	}
}


void Capture::parsing_beacon(const u_char *data, int length){
	beacon->rh = (struct radiotap_header *) data;
	beacon->bf = (struct beacon_frame *) (data + beacon->rh->len);
	beacon->fixed = (struct fixed_parameters *) (data + beacon->rh->len + 24);
	beacon->tag = (struct tagged_parameters *) (data + beacon->rh->len + 32);
	string bssid = char_to_string(beacon->bf->bssid);

	if(this->bmap.find(bssid) == this->bmap.end()){
		struct beacon_field	tmp_bd;
		this->bv.push_back(tmp_bd);
		this->bmap_p  = this->b_mapping(bssid);
		bmap_p->second.bssid = bssid;

		if ((beacon->fixed->capabilities[0] & 0x10 )!= 0x10 ){ bmap_p->second.encript.append("OPEN");}
		else { bmap_p->second.encript = "WPA"; }

		int offset = 0;
		while(offset < (length - (beacon->rh->len + 40))){
			beacon->tag = (struct tagged_parameters *) (data + beacon->rh->len + sizeof(*(beacon->bf)) + sizeof(*(beacon->fixed)) + offset);
			if(beacon->tag->flag == 0 ){
				bmap_p->second.essid = ssid_to_str(beacon->tag->data,int(beacon->tag->length));
				offset += (int(beacon->tag->length) + 2 );
			}

			else if(beacon->tag->flag == 0x03){
				bmap_p->second.channel = beacon->tag->data[0];
				offset += 3;
			}

			else if(beacon->tag->flag == 0x30){
				bmap_p->second.encript = "WPA2";
				if (int(beacon->tag->data[int(beacon->tag->length)-3]) == 2) bmap_p->second.auth.append("PSK");
				if (int(beacon->tag->data[int(beacon->tag->length)-9]) == 4) bmap_p->second.cipher.append("CCMP");
				if (int(beacon->tag->data[int(beacon->tag->length)-9]) == 2) bmap_p->second.cipher.append("TKIP");
				offset += int(beacon->tag->length)+2;
			}
			else {  offset += int(beacon->tag->length) +2;}
		}
		bmap_p->second.bssid = bssid;
		bmap_p->second.pwr = beacon->rh->antenna_signal;
		bmap_p->second.beacon_count = 0;
	}
	else{
		this->bmap.find(bssid)->second.beacon_count++;
		this->bmap.find(bssid)->second.pwr = beacon->rh->antenna_signal;
	}
}




int Capture::typecheck(const u_char *data){
	u_int16_t *length = (u_int16_t *) (data + 2);
	u_int8_t *type = (u_int8_t *) (data + *length);
	u_int8_t *flag = (u_int8_t *) (data + *length + 1);
	if (int(*type) == 80) return 1; // 2 = Probe
	if (int(*type) == 40 || int(*type) == 50) return 2; // 1 = Probe
	return 0;
}
string Capture::char_to_string(u_int8_t mac[]){
	char test[18];
	sprintf(test,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return test;
}

string Capture::ssid_to_str(uint8_t data[],int length){
	string ret = "";
	char tmp[32] = {0,};
	if(length > 32 ) length = 30;
	copy(data,data+length,tmp);
	ret.append(tmp);
	memset(tmp,0,length+1);
	return ret;
}
