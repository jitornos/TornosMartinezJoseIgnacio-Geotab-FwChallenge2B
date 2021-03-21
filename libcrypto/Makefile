TARGET?=libcrypto.so

CROSS_COMPILE?=

CC=$(CROSS_COMPILE)gcc
STRIP=$(CROSS_COMPILE)strip

include libcrypto_version

OBJS=src/crypto.o 

INCS := -I"./include"

ifeq ($(OPTIMIZATION),NO)
	OPTFLAGS= 
else
	OPTFLAGS= -Os
endif

CFLAGS= -Wall -g $(INCS) $(OPTFLAGS) -DVERSION=\"$(VERSION)\"
LD_FLAGS := -shared 

all: $(TARGET)  
		
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LD_FLAGS)
	mv $(TARGET) $(TARGET).sym
	$(STRIP) --strip-debug $(TARGET).sym -o $(TARGET)
	@ls -lisa $(TARGET)
	@ls -lisa $(TARGET).sym

clean: 
	rm -f `find . -name "*.o"`
	rm -f $(TARGET) $(TARGET).sym
