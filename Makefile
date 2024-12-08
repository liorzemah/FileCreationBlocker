PROJ=main
obj-m := $(PROJ).o
WATCHED_DIR=/home

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test:
	sudo insmod ./$(PROJ).ko
	sudo dmesg | tail
	sudo touch $(WATCHED_DIR)/malicious.txt || echo "Fail to create $(WATCHED_DIR)/malicious.txt"
	umask 0 | touch $(WATCHED_DIR)/valid.txt || echo "Fail to create file in $(WATCHED_DIR)/valid.txt"
	sudo touch $(WATCHED_DIR)/try.malicious.temp || echo "Fail to create file in $(WATCHED_DIR)/try.malicious.temp"
	sudo rmmod $(PROJ)
	sudo dmesg | tail

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean