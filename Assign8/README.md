## Buffer Overflow Exploitation

### Description

The C program "Greeter" has a buffer overflow vulnerability on using gets() 
without checking input length. Thus, an attacker can exploit this by injecting
code using the input. This is called Arbitrary Code Execution, and we are using
a shellcode which spawns a dash shell.

##### Usage
The python input generator is compiled using python2.7.

Run the shellcode test as:
```bash
make run
``` 

##### Implementation 

Since we have the global variable Name and the for loop at lines 21-22, 
we can use $Name to run the shellcode because $Name's memory pages 
have been set executable using mprotect (line 21). To use $Name to spawn
the shellcode, we need to jump to $Name's memory, which is done by 
changing the return address of readString to point to $Name. Specifically,
we jump to $Name + 52 to ignore all the buffer's values and start at memory 
containing nop and the shellcode.

The input contains 
1. A random string (multiple 'a') to fill the buffer
2. The return address in which readString will jump to ($Name + 52)
3. A series of Nop (0x90) to use a range in which the shellcode could be stored
4. The shellcode

The idea is that we change the return address of a function to point to 
the memory that we have installed the code.

##### Known issues

The python program will not produce correct input with newest versions of python 
due to different interpretations of hex values so it is advised to use 2.7 which is tested.