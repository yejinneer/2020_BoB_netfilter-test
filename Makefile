all: netfilter-test

netfilter-test: nf_test.c
	gcc nf_test.c -lnetfilter_queue

