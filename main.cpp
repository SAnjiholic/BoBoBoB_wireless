#include "capture.h"

int main(int argv, char **argc){
	Capture *cp = new Capture(argc[1]);
	cp->start();
}
