all: send-arp

send-arp: send-arp.o
	g++ -o send-arp send-arp.o -lpcap

send-arp.o:
	g++ -c -o send-arp.o send-arp.cpp

clean:
	rm -f send-arp
	rm -f *.o
