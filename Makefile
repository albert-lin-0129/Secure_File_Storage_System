.PHONY: main
main: build post 

build:
	gcc -O0 -g -m32 -fno-stack-protector -o stor stor.c malloc-2.7.2.c

post:
	execstack --set-execstack stor

.PHONY: clean
clean:
	rm -v stor
	rm -v enc.db
