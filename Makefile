osx_airodump : osx_airodump.o
	g++  -o osx_airodump osx_airodump.o -lpcap
	rm osx_airodump.o

osx_airodump.o:	main.cpp
	g++ -c -o osx_airodump.o main.cpp

clean :
	rm osx_airodump 2>/dev/null
	
