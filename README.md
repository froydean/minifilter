Minifilter that track who opens certain files, and controll access to them by DAC. Dac table in 2 cfg files.

Driver for the file system(minifilter) using visual studio template.
Compiler of visual studio 2015 community(14.0.25420.1). Build Release x64.
WDK(10.0.14393.0). SDK(10.1.14393.795). Runs on win10x64.

Instruction.
Used software:
OSRLOADER by administartor to register. Choose path to the .sys file(c:\\windows) and minifilter option.
DebugView64 by administrator to track kernel debug messages. Choose capture kernel.

.inf, .sys, cfgAcl.txt, cfgExecutors.txt should be placed in %SystemRoot% dir aka c:\\windows.

To initiate IRP read, write, examples:
"rw_simple.exe test1.txt w hello"
"rw_simple1.exe test2 r"


Content.

rw_simple is simple write/read c++ program.

cfgAcl.txt, cfgExecutors.txt is DAC table.

ACL strngs(cfgAcl):
test1.txt admin rw
test1.txt user1 r

(cfgExecutors):
rw_simple.exe admin
rw_simple1.exe user1

Main job:
Minifilter reads DAC table. Intercept IRP packets only search for (IRP_MJ_READ - 0x3, IRP_MJ_WRITE - 0x4)
Tracks only declared files and proccesses in cfg files.
According to DAC permit or allow acces to read/write. It will also displayed as debug messages.