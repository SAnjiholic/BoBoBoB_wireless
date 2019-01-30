#include <algorithm>
#include "capture.h"
#include <unistd.h>
#include <thread>

class Display{
	public:

		static void start(map<string, struct beacon_field> *bp, map<string, struct probe_field> *pp){
			auto m1 = *bp;
			auto m2 = *pp;

			auto bmap_p = m1.begin();
			auto pmap_p = m2.begin();
			while(1){
				system("clear");
				printf("%-18s %3s %7s %5s %3s %3s %6s %6s %6s %6s %10s \n","BSSID","PWR","Beacons","#Data","#/s","CH","MB","ENC","CIPHER","AUTH","ESSID");
				for(auto bmap_p = bp->begin(); bmap_p != bp->end(); bmap_p++){
					if(bmap_p->second.essid != ""
							&& bmap_p->second.essid[0] >0x29 
							&& int(bmap_p->second.beacon_count) > 0){

						printf("%-18s %3d %7d %5d %3d %3d %6s %6s %6s %6s %10s \n",
								bmap_p->second.bssid.c_str(),
								int(bmap_p->second.pwr),
								int(bmap_p->second.beacon_count),
								bmap_p->second.data, //#data
								//0, //#data
								0, //D/S
								int(bmap_p->second.channel),
								"", //MB
								//bmap_p->second.maximum_speed,
								bmap_p->second.encript.c_str(),
								bmap_p->second.cipher.c_str(),
								bmap_p->second.auth.c_str(),
								bmap_p->second.essid.c_str());
					}
				}
				printf("\n\n%-18s %-18s %3s %7s %5s %5s %10s \n","BSSID","STATION","PWR","RATE","Lost","Frames","Probe");
				int i = 0;
				for(auto pmap_p = pp->begin(); pmap_p != pp->end(); pmap_p++){
					if(pmap_p->second.station != ""){
						printf("%-18s %-18s %5d %7s %5d %5d %10s \n",
								pmap_p->second.bssid.c_str(),
								pmap_p->second.station.c_str(),
								int(pmap_p->second.pwr),
								"0", //rate
								0, //rost
								0, //frames
								"Probe"); //probe
					}
					if( i == 20 ) break;
					i++;
				}
				usleep(50000);
			}
		}

};

