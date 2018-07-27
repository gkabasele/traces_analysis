C			= gcc
CFLAGS		= -c -g -Wall -D_GNU_SOURCE
LDFLAGS		= -lpcap 
DEBFLAGS 	= -g
SOURCES		= shift_time.c 
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= bin/shift_time
LOG			= log.txt

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
		$(CC)  $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
		$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

logs:
		sudo ./$(TARGET) > $(LOG)
exec:
		sudo ./$(TARGET) 
clean:
	rm -rf $(OBJECTS) $(TARGET)
