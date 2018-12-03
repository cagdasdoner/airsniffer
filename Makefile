obj-m += tcpsniff.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc tcpread.c -o tcpread.o

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean