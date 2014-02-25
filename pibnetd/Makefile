TARGET=pibnetd pibping
OBJS=main.o smp.o perf.o logger.o
CFLAGS=-g -Wall

ALL: $(TARGET)

pibnetd: $(OBJS)
	gcc $(CFLAGS) $^ -o $@

pibping: pibping.c
	gcc $(CFLAGS) $^ -o $@

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: clean
