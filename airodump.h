#include "struct.h"
#include <pcap.h>
#include <vector>
#include <string>
#include <map>
using namespace std;

class CommonHeader{
	public:
		struct radiotap_header *rh;
		struct rsn_field24 *rsn;
		struct tagged_parameters *tag;
		struct fixed_parameters *fixed;
		void parsing_tagged();
		CommonHeader();
		~CommonHeader();
};

class Beacon: public CommonHeader{
	public:
		struct beacon_frame *bf;
		struct beacon_field *bd;
		Beacon();
		~Beacon();
};

class Probe: public CommonHeader{
	public:
		struct probe_frame *pf;
		struct probe_field *pd;
		Probe();
		~Probe();
};

class Save_data{
	private:
		map<string,struct beacon_field>::iterator bmap_p;
		map<string,struct probe_field>::iterator pmap_p;
	public:
		map<string,struct beacon_field> bmap;
		map<string,struct probe_field> pmap;
		vector<struct beacon_field> bv;
		vector<struct probe_field> pv;
		map<string,struct beacon_field>::iterator b_mapping(string id);
		map<string,struct probe_field>::iterator p_mapping(string id);

};

map<string,struct beacon_field>::iterator Save_data::b_mapping(string id){
	this->bmap.insert(make_pair(id,this->bv.back()));
	this->bmap_p = this->bmap.find(id);
	return this->bmap_p;
}

map<string,struct probe_field>::iterator Save_data::p_mapping(string id){
	this->pmap.insert(make_pair(id,this->pv.back()));
	this->pmap_p = this->pmap.find(id);
	return this->pmap_p;
}

class Capture{
	private: 
		struct pcap_pkthdr *header;
		struct radiotap_header *rdt;
		Save_data *save_data;
		pcap_t *handle;
		Beacon *beacon;
		Probe *probe;
		const u_char *data;
		char *errbuf;
		int pcap_check;
		int typecheck(const u_char *data);
	public:
		Capture();
		Capture(char *dev);
		~Capture();
		void display();
		bool start();
		string char_to_string(u_int8_t mac[]);
		string ssid_to_str(uint8_t data[],int length);

};		

Capture::Capture(char *dev){
	beacon = new(Beacon);
	probe = new(Probe);
	save_data = new(Save_data);

	if(sizeof(dev) == 0 ) cout << "Insert Dev  :( " << endl; 
	handle = pcap_create(dev,errbuf);
	if(handle == NULL) exit(-1);
	if(pcap_set_rfmon(handle,1) == 0 ) cout << "monitor mode enabled" << endl;
	pcap_set_snaplen(handle,2048);
	pcap_set_promisc(handle,0);
	pcap_set_timeout(handle,512);
	pcap_activate(handle);
}

bool Capture::start(){
	while ((pcap_check = pcap_next_ex(handle,&header,&data)) >= 0 ){
		if(pcap_check == 0) continue;
		//rdt = (struct radiotap_header *) data;
		int type = typecheck(data);

		switch(type) {
			case 1:{  	// beacon
					   beacon->rh = (struct radiotap_header *) data;
					   beacon->bf = (struct beacon_frame *) (data + beacon->rh->len);
					   beacon->fixed = (struct fixed_parameters *) (data + beacon->rh->len + 24);
					   beacon->tag = (struct tagged_parameters *) (data + beacon->rh->len + 32);
					   string bssid = char_to_string(beacon->bf->bssid);

					   if(save_data->bmap.find(bssid) == save_data->bmap.end()){
						   beacon->bd = new struct beacon_field;
						   save_data->bv.push_back(*(beacon->bd));
						   auto map = save_data->b_mapping(bssid);
						   map->second.bssid = bssid;

						   if ((beacon->fixed->capabilities[0] & 0x10 )!= 0x10 ){ map->second.encript.append("OPEN");}
						   else { map->second.encript = "WPA"; }

						   int offset = 0;
						   while(offset < (header->len - beacon->rh->len + 32)){
							   if(beacon->tag->flag == 0 && beacon->tag->length != 0 && beacon->tag->data[0] > 0x29  && beacon->tag->data[0] < 0x5b ){
								   map->second.essid = ssid_to_str(beacon->tag->data,int(beacon->tag->length));
								   offset += (int(beacon->tag->length) + 2 );
							   }
							   
							   else if(beacon->tag->flag == 0x03){
								   map->second.channel = beacon->tag->data[0];
								   offset += 3;
							   }
							   
							   else if(beacon->tag->flag == 0x30){
								   map->second.encript = "WPA2";
								   if (int(beacon->tag->data[int(beacon->tag->length)-3]) == 2) map->second.auth.append("PSK");
								   if (int(beacon->tag->data[int(beacon->tag->length)-9]) == 4) map->second.cipher.append("CCMP");
								   if (int(beacon->tag->data[int(beacon->tag->length)-9]) == 2) map->second.cipher.append("TKIP");
								   offset += int(beacon->tag->length)+2;
							   }
							   else {  offset += int(beacon->tag->length) +2;}
						   }
						   map->second.bssid = bssid;
						   map->second.pwr = rdt->antenna_signal;
						   map->second.beacon_count = 0;
					   }
					   else{
						   save_data->bmap.find(bssid)->second.beacon_count++;
					   }
					   break;
				   }

			case 2:{		// probe
					   probe->rh = (struct radiotap_header *) data;
					   probe->pf = (struct probe_frame *) (data + probe->rh->len);
					   probe->fixed = (struct fixed_parameters *) (data + probe->rh->len + 24);
					   probe->tag = (struct tagged_parameters *) (data + probe->rh->len + 32);
					   string bssid = char_to_string(probe->pf->bssid);
					   string station = "";

					   if (bssid != "ff:ff:ff:ff:ff:ff" && save_data->bmap.find(bssid) != save_data->bmap.end()){
						   struct probe_field tmp_pf;
						   probe->pd = &tmp_pf;
						   if(probe->pf->frame_field == 0x0040){
							   station = char_to_string(probe->pf->source_addr);
						   }
						   else if (probe->pf->frame_field == 0x0050){
							   station = char_to_string(probe->pf->destination_addr);
						   }
						   if(save_data->pmap.find(station) == save_data->pmap.end()){
							   save_data->pv.push_back(tmp_pf);
							   
							   auto p_map = save_data->p_mapping(station);
							   p_map->second.bssid = bssid;
							   p_map->second.station = station;
							   p_map->second.pwr = probe->rh->antenna_signal;
							   p_map->second.lost = 0;
							   p_map->second.frame = 0;
						   }
					   }
				break;
				   }

			case 3: {	// Data
				break;
					}
		}
	}
}

int Capture::typecheck(const u_char *data){
	u_int16_t *length = (u_int16_t *) (data + 2);
	u_int8_t *type = (u_int8_t *) (data + *length);
	u_int8_t *flag = (u_int8_t *) (data + *length + 1);
	if (int(*type) == 8) return 1; // 2 = Probe
	if (int(*type) == 4 || int(*type) == 5) return 2; // 1 = Probe
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
