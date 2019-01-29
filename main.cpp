#include "display.h"

int main(int argv, char **argc){
	Capture *cp = new Capture(argc[1]);
	Display *dp = new Display();
	map<string,struct beacon_field> *bmap;
	map<string,struct probe_field> *pmap;
	bmap = &(cp->bmap);
	pmap = &(cp->pmap);
	//thread t1(start, bmap, pmap);
	auto start = Display::start;	
	thread t1(start, bmap, pmap);
	cp->start();
	t1.join();
}
