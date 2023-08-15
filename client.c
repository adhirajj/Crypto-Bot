#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_MESSAGE_LENGTH 256
#define FLAG_LENGTH 64
#define MAXLINE 2048

// Function to decrypt the received message using the substitution cipher
char* decrypt_message(const char* cipher_alphabet, const char* message) {
    // Calculate the length of the message
    size_t msg_len = strlen(message);

    // Allocate memory for the decrypted message (including null terminator)
    char* decrypted_msg = (char*)malloc(msg_len + 1);
    if (decrypted_msg == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        exit(EXIT_FAILURE);
    }

    // Perform decryption by looking up each character in the cipher alphabet
    for (size_t i = 0; i < msg_len; i++) {
        char ch = message[i];
        if ('a' <= ch && ch <= 'z') {
            // Convert the character to its corresponding decrypted character
            int index = ch - 'a';
            decrypted_msg[i] = cipher_alphabet[index];
        } else {
            // Non-alphabetic characters remain unchanged
            decrypted_msg[i] = ch;
        }
    }

    // Null-terminate the decrypted message
    decrypted_msg[msg_len] = '\0';

    return decrypted_msg;
}


int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <Identification> <Port> <Host IP Address>\n", argv[0]);
        return 1;
    }

    const char* identification = argv[1];
    int port = atoi(argv[2]);
    const char* host_ip = argv[3];

    int sockfd;
    struct sockaddr_in server_addr;

    // Step 1: Open a TCP stream socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host_ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return 1;
    }

    // Step 2: Connect to the remote server

    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    // Step 3: Send identification to the server
    char identification_msg[MAXLINE];
    snprintf(identification_msg, MAXLINE, "cs230 HELLO %s\n", identification);
    if (send(sockfd, identification_msg, strlen(identification_msg), 0) == -1) {
        perror("send");
        close(sockfd);
        return 1;
    }

    // Buffer to receive and store server responses
    char response[MAXLINE];
    //size_t response_len = 0;

    // Step 4 to Step 6: Decrypt messages and send back decrypted results
    while (1) {
        // Step 4: Receive the status message
        ssize_t n = recv(sockfd, response, MAXLINE - 1, 0);
        if (n <= 0) {
            if (n == 0) {
                // Connection closed by server
                break;
            } else {
                perror("recv");
                close(sockfd);
                return 1;
            }
        }
	
        response[n] = '\0';

	//Printing received response
       	printf("Received Response: %s\n", response);

        // Parse the status message
        char cipher_alphabet[MAXLINE];
        char message[MAXLINE];
        if (sscanf(response, "cs230 STATUS %s %s", cipher_alphabet, message) == 2) {
	  //Step 5: Decrypt the message
	  char* decrypted_message = decrypt_message(cipher_alphabet, message);

	  //Step 6: Send decrypted message back to the server;
	  char decrypted_msg[MAXLINE];
	  sprintf(decrypted_msg, "cs230 %s\n", decrypted_message);
	  if (send(sockfd, decrypted_msg, strlen(decrypted_msg), 0) == -1) {
	    perror("send");
	    close(sockfd);
	    return 1;
	  }

	  free(decrypted_message);
	  
        }else if (sscanf(response, "cs230 %*s BYE") == 0) {
	  printf("Received Flag: %s\n", response + strlen("cs230 "));
	  break;
	}else {
	  fprintf(stderr, "Invalid response format: %s\n", response);
          close(sockfd);
          return 1;
	}
    }
    
    // Step 7: Receive the flag
    ssize_t n = recv(sockfd, response, MAXLINE - 1, 0);
    if (n > 0) {
        response[n] = '\0';
        printf("Flag: %s\n", response);
    }

    char cypher[MAXLINE] = "zyxabcdefghijklmnopqrstuvw";
    char message[MAXLINE] = "zzyyxx";
    //    printf("Test- %s\n", decrypt_message(cypher, message));

    // Close the socket
    close(sockfd);

    return 0;
}

