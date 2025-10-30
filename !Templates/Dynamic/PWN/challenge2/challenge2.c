#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_BUFFER_SIZE 128
#define SECRET_BUFFER_SIZE 64

int ancient_password = 0x13371337;

// Function to read and print the flag
void read_flag() {
    char secret[SECRET_BUFFER_SIZE];
    FILE *file = fopen("flag.txt", "r");
    
    if (!file) {
        perror("Error opening flag file");
        exit(EXIT_FAILURE);
    }

    fgets(secret, SECRET_BUFFER_SIZE, file);
    fclose(file);

    printf("Unlocking ancient secrets...\n");
    printf("Here is your reward: %s\n", secret);
}

int validate_access() {
    if (ancient_password == 0x44554455) {
        return 1;  // Access granted
    }
    return 0;  // Access denied
}

void process_input() {
    char user_input[INPUT_BUFFER_SIZE];

    printf("You don't have what it takes. Only a true historian could change my suspicions. What do you have to say?\n");
    fflush(stdout);
    
    fgets(user_input, sizeof(user_input), stdin);

    printf("You said: ");
    printf(user_input);  // Vulnerable to format string exploit
    printf("\n");

    if (validate_access()) {
        read_flag();
    } else {
        printf("ancient_password = 0x%x\n", ancient_password);
        printf("You can do better!\n");
        fflush(stdout);
    }
}

int main() {
    setbuf(stdout, NULL);

    while (1) {
        process_input();
    }

    return 0;
}
