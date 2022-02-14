LDLIBS += -lpcap

all: beacon-flood

deauth-attack: beacon-flood.cpp

clean:
	rm -f beacon-flood *.o
