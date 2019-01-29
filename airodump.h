#include <iostream>
#include <unistd.h>
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
	//	CommonHeader();
	//	~CommonHeader();
};

class Beacon: public CommonHeader{
	public:
		struct beacon_frame *bf;
		struct beacon_field *bd;
	//	Beacon();
	//	~Beacon();
};


class Probe: public CommonHeader{
	public:
		struct probe_frame *pf;
		struct probe_field *pd;
	//	Probe();
	//	~Probe();
};


class Save_data{
	public:
		map<string,struct beacon_field>::iterator bmap_p;
		map<string,struct probe_field>::iterator pmap_p;
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


