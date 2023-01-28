import re
import struct
import dis
from capstone import *

    
#patt1=re.compile(b".{0,16}\x48\x89\xfb.{0,16}\xc3")
#patt1=re.compile(b"\x52.{0,16}\x5c.{0,16}\xc3")
patt1=re.compile(b"\x48\x89\xDF.{0,16}\xc3")
f=open("XXX","rb")
a=f.read()
f.close()

x=[]
for each in patt1.findall(a):
    #print(struct.unpack(">BBB",each))
    if each not in x:
        x.append(each)
for each in x:
    #print("####")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    disam_string=""
    for i in md.disasm(each, 0x00):
        disam_string=disam_string+"0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str)
    if "ret\t\n" in disam_string and "call" not in disam_string and "jne" not in disam_string:
        print(repr(each))
        print(disam_string)
z=b'H\x89\xdf[A\\H\x89\xf8A]A^]\xc3'
for i in range(len(z)):
    print("%02x "%z[i],end="")
