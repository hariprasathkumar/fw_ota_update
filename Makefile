obj-m := pmic-download.o                       
PWD := $(shell pwd)

all:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -C /home/hari/kernel/rpi-kernel M=$(PWD) modules


clean:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- -C /home/hari/kernel/rpi-kernel m=$(PWD) clean
