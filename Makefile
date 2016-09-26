default:
	gcc -Wall ideviceunback.c -o ideviceunback -lssl -lcrypto

clean:
	rm ideviceunback
