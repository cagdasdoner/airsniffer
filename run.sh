make all
sudo rmmod tcpsniff
sudo insmod tcpsniff.ko
#insert to udev to remove nod permission modification
sudo chmod 666 /dev/sniffa
./tcpread.o
