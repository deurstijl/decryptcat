/*
    Encryption key brute-force tool for cryptcat encrypted data
    Uses the cryptcat supplied twofish implementation to brute-force 
    the encryption key based on a supplied word-list.
    Based on the original farm9crypt.cc included in the cryptcat source
*/

#include <string.h>
#include <stdio.h>
#include <sys/types.h>    // suggested by several people -- for OpenBSD, FreeBSD compiles
#include <sys/socket.h>     /* basics, SO_ and AF_ defs, sockaddr, ... */
#include <stdlib.h>
#include "farm9crypt.h"

int checkpass(char* ciphertext, int size, char* password){
    int res;
    // First initialize twofish
    farm9crypt_init(password);
    // Check if twofish has initialized:
    res = farm9crypt_initialized();
    if (res != 1){
        printf("ERROR initialising twofish with password %s.\n",password);
        return(1);
    }
    // Now try to decrypt the block
    int result=decryptcat_checkpass(ciphertext,size);
    return(result);
}

int main( int argc, char *argv[] ){
    // Check command line arguments
    if ( argc != 3){
        printf("Decryptcat by @deurstijl,\n");
        printf("To brute-force the encryption password for a cryptcat encrypted payload.\n");
        printf("\nUsage: %s Encrypted_file Wordlist_file\n",argv[0]);
        return(1);
    }
    int result;
    int ret;
    // Read the first 32 bytes of the cipher file
    char* encryptedfile=argv[1];
    char ciphertext[32];
    FILE *fp;
    fp = fopen(encryptedfile,"r"); // read mode
    if( fp == NULL )
    {
        perror("Error while opening the encrypted file.\n");
        exit(EXIT_FAILURE);
    }
    ret=fread(ciphertext,32,1,fp);
    fclose(fp);
    
    // Loop through the wordlist
    char* wordfile=argv[2];
    char* line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen(wordfile, "r");
    if( fp == NULL )
    {
        perror("Error while opening the wordlist.\n");
        exit(EXIT_FAILURE);
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        // Replace the newline at the end with a \x00
        line[read-1]='\x00';
        result=checkpass(ciphertext,32,line);
        if (result == 1337){
            printf("Decryption successfull with password: %s\n",line);
            break;
        }
    }

    fclose(fp);
    if (line)
        free(line);

    return(0);
}

