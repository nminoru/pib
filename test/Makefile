TARGETS = \
	test-ipoib-01 \
	test-ib_reg_mr-01 \
	comp_vector \
	show_mem_reg \
	qp-roundrobin \
	query_pkey

CFLAGS  = -g -O1 -Wall -D_GNU_SOURCE

LIBS    = -libverbs -lpthread -lrt -lm

ALL: $(TARGETS)

$(TARGETS): %: %.c
	gcc $(CFLAGS) $(LIBS) $^ -o $@

clean:
	rm -f $(TARGETS) *.o *~

.PHONY: clean
