# How to build the example
To build the WolfSSL library and create a TLS 1.3 client and server application on an Ubuntu machine, follow these steps:

1. Install Build Dependencies:

	You'll need some development tools and dependencies. Open a terminal and run the following commands to install the required packages:
	
	- sudo apt update \
	- sudo apt install build-essential cmake pkg-config 

2. Download and Compile WolfSSL:

	Download the WolfSSL source code from the official website (https://www.wolfssl.com/download/) or using the following commands:
	
	wget https://www.wolfssl.com/dl/wolfssl-5.4.1-stable.tar.gz \
	tar -xzvf wolfssl-5.4.1-stable.tar.gz \
	cd wolfssl-5.4.1-stable \

	Configure and compile WolfSSL: 
	
	./configure --enable-tls13 \
	make \
	sudo make install \
	The --enable-tls13 flag enables TLS 1.3 support.

4. Compile the Applications:
  To compile the client and server applications, you can use gcc. Make sure to link against the WolfSSL library:\
	
	For the client:
	- gcc -o tls_client tls_client.c -lwolfssl
	
	For the server:
	- gcc -o tls_server tls_server.c -lwolfssl

