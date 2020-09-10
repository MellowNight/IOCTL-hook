# realExtern
kernel driver that hooks ioctl with multiple abilities such as sig scanning and read/writing

it simply places a mov rax, xxx jmp rax inside of DiskDeviceControl and directs code flow to realExtern.sys

hook offsets may change across windows updates.


## WARNING:

it is detected and the code is very messy


read this source for an example of how to use:


