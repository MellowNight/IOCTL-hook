# realExtern
kernel driver that hooks ioctl with multiple abilities such as sig scanning and read/writing

it simply places a mov rax, xxx jmp rax inside of DiskDeviceControl and directs code flow to realExtern.sys


WARNING:

it is detected


read this source for an example of how to use:

https://github.com/jguo12/RealExtern-example-glow
