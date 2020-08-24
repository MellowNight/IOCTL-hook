# realExtern
kernel driver that hooks ioctl with multiple abilities such as sig scanning and read/writing

it simply places a mov rax, xxx jmp rax inside of DiskDeviceControl and directs code flow to realExtern.sys

hook offsets may change across windows updates.

## hook offsets
1903-1909 windows hook offsets: 0x112E and 2D90

2004 windows hook offsets: 0x16AF and 0x32A2


(search for these values in the driver.cpp)


## WARNING:

it is detected and the code is very messy

## NOTE: I am the real creator of this driver, other people have been trying to take credit for my work (its not a good driver anyways)
