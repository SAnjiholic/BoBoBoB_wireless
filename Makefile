osx_airodump : osx_airodump.o
	g++  -o osx_airodump osx_airodump.o -lpcap -std=c++11
	rm osx_airodump.o

osx_airodump.o:	main.cpp
	g++ -c -o osx_airodump.o main.cpp -std=c++11

clean :
	rm osx_airodump 2>/dev/null
	
