# Makefile for fw2b application to encryp

TARGET?=fw2b
LIBCRYPTO?=crypto

CROSS_COMPILE?=

CC=$(CROSS_COMPILE)gcc
STRIP=$(CROSS_COMPILE)strip

OBJS=src/main.o

INCS=-I"./include" \
	-I"../libcrypto/include"

LIBS=-L"../libcrypto"

ifeq ($(OPTIMIZATION),NO)
	OPTFLAGS= 
else
	OPTFLAGS= -Os
endif

CFLAGS= -Wall -g $(INCS) $(OPTFLAGS)
LD_FLAGS= $(LIBS) -l$(LIBCRYPTO)

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
