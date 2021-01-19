all: Greeter

Greeter: Greeter.c
	gcc -Wl,-z,norelro -ansi -static -fno-stack-protector -z execstack -g -no-pie -m32 Greeter.c -o Greeter

input:
	python2.7 genInput.py > input

run:
	./Greeter < input

clean:
	rm Greeter input
