osx_airodump : osx_airodump.o
	g++  -o osx_airodump osx_airodump.o -lpcap

osx_airodump.o:	main.cpp
	g++ -c -o osx_airodump.o main.cpp

clean :
	rm *.o osx_airodump
