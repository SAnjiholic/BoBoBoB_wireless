#include <stdio.h>
#include <iostream>
#include <string>
#include <map>
#pragma pack(push, 1)

using namespace std;

struct radiotap_header{
	u_int8_t 	version;     /* set to 0 */
    u_int8_t 	pad;
	u_int16_t 	len;         /* entire length */
	u_int32_t	present;     /* fields present */
	u_int64_t	timestamp;
	u_int8_t	flags;
	u_int8_t	rate; // 500 * x
	u_int16_t	frequency; // 
	u_int16_t	cha_flags;
	int8_t 		antenna_signal; //signed
	int8_t 		antenna_noise; //signed
	u_int8_t	antenna; // channel
};

struct beacon_frame{
	u_int16_t	frame_field;
	u_int16_t	duration;
//	u_int8_t	reveiver_addr[6];
	u_int8_t	destination_addr[6];
//	u_int8_t	transmitter_addr[6];
	u_int8_t	source_addr[6];
	u_int8_t	bssid[6];
	u_int16_t	sequence; //12bit
};
struct probe_frame{
	u_int16_t	frame_field;
	u_int16_t	duration;
//	u_int8_t	reveiver_addr[6];
	u_int8_t	destination_addr[6];
//	u_int8_t	transmitter_addr[6];
	u_int8_t	source_addr[6];
	u_int8_t	bssid[6];
	u_int16_t	sequence; //12bit
};


struct fixed_parameters{
	u_int64_t	timestamp;
	u_int16_t	interval;
	u_int8_t	capabilities[2];
};

struct tagged_parameters{
	u_int8_t	flag;
	u_int8_t	length;
	//u_int8_t	data[100];
	u_int8_t	data[0];
};

struct dot11_header{
	struct radiotap_header rt_h;
	struct beacon_frame beacon_h;
	struct fixed_parameters fixed_h;
};

struct rsn_field20{
	u_int8_t	flag;
	u_int8_t	length;
	u_int16_t	version;
	u_int32_t	group_cipher_suite; // 00:0f:ac 2 or 4
	u_int16_t	pairwire_count;
	u_int32_t	pairwire_list;
	u_int16_t	auth_key_count;
	u_int32_t	auth_key_list;
	u_int16_t	rsn_capabilities;
};	
struct rsn_field24{
	u_int8_t	flag;
	u_int8_t	length;
	u_int16_t	version;
	u_int32_t	group_cipher_suite; // 00:0f:ac 2 or 4
	u_int16_t	pairwire_count;
	u_int64_t	pairwire_list;
	u_int16_t	auth_key_count;
	u_int32_t	auth_key_list;
	u_int16_t	rsn_capabilities;
};	


struct beacon_field{
	string		bssid;
	int8_t		pwr;
	u_int8_t	beacon_count;
	int8_t		data;
	int8_t		data_per_second;
	u_int8_t	channel;
	u_int8_t	maximum_speed;
	string		encript;
	string		cipher;
	string		auth;
	string		essid;
};

struct probe_field{
	string bssid;
	string station;
	int8_t	pwr;
	string rate;
	u_int16_t lost;
	u_int16_t frame;
	string probe;
};

class gkrltlfgek{
	public:
	string		bssid; // 
	int8_t		pwr; // 
	u_int8_t	beacon_count; // 
	int8_t		data;
	int8_t		data_per_second;
	u_int8_t	channel; 
	u_int8_t	maximum_speed;
	string		encript;
	string		cipher;
	string		auth;
	string		essid; // 
	gkrltlfgek(){
		bssid = "";
		pwr = 0;
		beacon_count = 0;
		data = 0;
		data_per_second = 0;
		channel = 0;
		maximum_speed =0;
		encript = "";
		cipher = "";
		auth = "";
		essid = "";
	}
};



	

