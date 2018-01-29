CC=gcc
CXX=g++
RM=-rm -f
OUTDIR = ./output
TARGET = cap_main

source = $(wildcard *.c)
object = $(patsubst %.c, $(OUTDIR)/%.o, $(source))

all:$(TARGET)

$(OUTDIR)/%.o:%.c
	$(CC) -c $< -o $@

$(TARGET):$(object)
	$(CC) -Wall -o $@ $(object) -lpthread 

.PHONY:default clean
clean:
	$(RM) $(TARGET) $(object)

install:
	sudo cp $(TARGET) /usr/local/bin
uninstall:
	sudo rm /usr/local/bin/$(TARGET)
