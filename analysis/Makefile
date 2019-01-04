C			= gcc
CFLAGS		= -c -g -Wall -D_GNU_SOURCE
LDFLAGS		= -lpcap 
DEBFLAGS 	= -g
SOURCES		= shift_time.c array.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= ../bin/shift_time
LOG			= log.txt
STAT_INC	= flows.c lists.c

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
		$(CC)  $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
		$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

timesplit:
	$(CC) -g -Wall -D_GNU_SOURCE timesplit.c -o ../bin/timesplit $(LDFLAGS) 

statistic:
	$(CC) -g -Wall -D_GNU_SOURCE $(STAT_INC) statistic.c -o ../bin/statistic $(LDFLAGS)

size:
	$(CC) -g -Wall -D_GNU_SOURCE $(STAT_INC) export_packet_size.c -o ../bin/packetSize $(LDFLAGS)

logs:
		sudo ./$(TARGET) > $(LOG)
exec:
		sudo ./$(TARGET) 
clean:
	rm -rf $(OBJECTS) $(TARGET)
