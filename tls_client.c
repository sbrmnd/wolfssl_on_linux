#include <wolfssl/options.h>  
#include <wolfssl/ssl.h>  
#include <wolfssl/test.h>  
#include <errno.h>  
#include <string.h>  
#include <arpa/inet.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <stdio.h>  
  
#define SERV_PORT 11111  
  

  
int main()  
{  
    int sockfd;  
    WOLFSSL_CTX* ctx;  
    WOLFSSL* ssl;  
    WOLFSSL_METHOD* method;  
    struct sockaddr_in servAddr;  
    const char message[] = "Hello, World!";  
  
    printf("Creating socket...\n");  
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  
        err_sys("socket creation failed");  
  
    memset(&servAddr, 0, sizeof(servAddr));  
    servAddr.sin_family = AF_INET;  
    servAddr.sin_port = htons(SERV_PORT);  
    //Connect to local host
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  
  
    printf("Connecting to server...\n");  
    if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)  
        err_sys("connect failed");  
    printf("Connected to server\n");  
  
    printf("Initializing WolfSSL library...\n");  
    wolfSSL_Init();  

    /* Enable debugging to print full handshake messages */  
    wolfSSL_Debugging_ON();  
    
    method = wolfTLSv1_3_client_method(); /* use TLS v1.3 */  
  
    printf("Creating SSL context...\n");  
    if ((ctx = wolfSSL_CTX_new(method)) == NULL)  
        err_sys("wolfSSL_CTX_new error");  
  
    printf("Creating SSL object...\n");  
    if ((ssl = wolfSSL_new(ctx)) == NULL)  
        err_sys("wolfSSL_new error");  
  
    printf("Loading CA certificate...\n");  
    if (wolfSSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", 0) != SSL_SUCCESS)  
        err_sys("Error loading certs/ca-cert.pem");  
  
    printf("Setting up SSL connection...\n");  
    wolfSSL_set_fd(ssl, sockfd);  
  
    printf("Performing SSL handshake...\n");  
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)  
        err_sys("wolfSSL_connect error");  
    printf("SSL handshake successful\n");  
  
    printf("Sending message to server...\n");  
    if (wolfSSL_write(ssl, message, strlen(message)) != strlen(message))  
        err_sys("wolfSSL_write error");  
    printf("Message sent successfully\n");  
  
    /* frees all data before client termination */  
    wolfSSL_free(ssl);  
    wolfSSL_CTX_free(ctx);  
    wolfSSL_Cleanup();  
  
    printf("Client closed\n");  
  
    return 0;  
}  

