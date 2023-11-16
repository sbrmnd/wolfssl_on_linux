#include <wolfssl/options.h>  
#include <wolfssl/ssl.h>  
#include <wolfssl/test.h>  
#include <errno.h>  
#include <arpa/inet.h>  
#include <sys/socket.h>  
#include <unistd.h>  
#include <stdio.h>  
  
#define SERV_PORT 11111  
#define MAX_LINE 4096  
  
 
  
int main() {  
    int listenfd, connfd;  
    WOLFSSL_CTX* ctx;  
    WOLFSSL* ssl;  
    int n;  
    char buf[MAX_LINE];  
    WOLFSSL_METHOD* method;  
    struct sockaddr_in servaddr, cliaddr;  
    socklen_t len;  
  
    /* Initialize wolfSSL library */  
    wolfSSL_Init();  

    /* Enable debugging to print full handshake messages */  
    wolfSSL_Debugging_ON();  
  
    /* Get encryption method for TLS 1.3 */  
    method = wolfTLSv1_3_server_method();  
  
    /* Create wolfSSL_CTX */  
    if ((ctx = wolfSSL_CTX_new(method)) == NULL)  
        err_sys("wolfSSL_CTX_new error");  
  
    /* Load server certs into ctx */  
    if (wolfSSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)  
        err_sys("Error loading certs/server-cert.pem");  
  
    /* Load server key into ctx */  
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)  
        err_sys("Error loading certs/server-key.pem");  
  
    /* create and set up listening socket */  
    listenfd = socket(AF_INET, SOCK_STREAM, 0);  
    if (listenfd < 0)  
        err_sys("socket creation failed");  
  
    memset(&servaddr, 0, sizeof(servaddr));  
    servaddr.sin_family = AF_INET;  
    //servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Connect to localhost
    servaddr.sin_port = htons(SERV_PORT); 

    printf("Server connected to %s:%d\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port)); 
  
    if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)  
        err_sys("bind failed");  

    printf("Server connected after bind to %s:%d\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port)); 
  
    if (listen(listenfd, 10) < 0)  
        err_sys("listen failed");  
  
    printf("Server listening on port %d\n", SERV_PORT);  
  
    len = sizeof(cliaddr);  
    connfd = accept(listenfd, (struct sockaddr*)&cliaddr, &len);  
    if (connfd < 0)  
        err_sys("accept failed");  
  
    printf("Accepted connection from %s:%d\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));  
  
    /* Create wolfSSL object */  
    if ((ssl = wolfSSL_new(ctx)) == NULL)  
        err_sys("wolfSSL_new error");  
  
    wolfSSL_set_fd(ssl, connfd);  
  
    if ((n = wolfSSL_read(ssl, buf, (sizeof(buf) - 1))) > 0) {  
        printf("Received data from client: %s\n", buf);  
        if (wolfSSL_write(ssl, buf, n) != n)  
            err_sys("wolfSSL_write error");  
    }  
  
    if (n < 0)  
        printf("wolfSSL_read error: %d\n", wolfSSL_get_error(ssl, n));  
    else if (n == 0)  
        printf("Connection closed by peer\n");  
  
    wolfSSL_free(ssl);  
    close(connfd);  
    wolfSSL_CTX_free(ctx);  
    wolfSSL_Cleanup();  
    close(listenfd);  
  
    printf("Server closed\n");  
  
    return 0;  
}  

