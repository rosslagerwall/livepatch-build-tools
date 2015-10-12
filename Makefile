SHELL = /bin/sh
CC    = gcc

.PHONY: all install clean
.DEFAULT: all

CFLAGS  += -Iinsn -Wall -g
LDFLAGS = -lelf

TARGETS = create-diff-object
OBJS = create-diff-object.o lookup.o insn/insn.o insn/inat.o
SOURCES = create-diff-object.c lookup.c insn/insn.c insn/inat.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

%.o : %.c
	$(CC) -MMD -MP $(CFLAGS) -c -o $@ $<

create-diff-object: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	$(RM) $(TARGETS) $(OBJS) *.d insn/*.d
