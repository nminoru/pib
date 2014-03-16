TARGETS = test-ipoib-01

CFLAGS  = -g -O1 -Wall -D_GNU_SOURCE

# LIBS    = -libverbs -lpthread -lrt -lm

ALL: $(TARGETS)

$(TARGETS): %: %.c
	gcc $(CFLAGS) $(LIBS) $^ -o $@

clean:
	rm -f $(TARGETS) *.o *~

.PHONY: clean
