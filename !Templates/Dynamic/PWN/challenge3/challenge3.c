#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BALANCE_THRESHOLD 200000
#define USERNAME "u$3rqP/8qmnP2"
#define PASSWORD "dE20sWj1KQ6WPzE"
#define DISCOUNTED 1200

int balance = 1000;  // Initial balance as unsigned int

void display_balance() {
    printf("Your current balance is: $%u\n", balance);
}

void redeem_voucher() {
    int voucher;
    int total_cost;  // Declare total_cost as int to allow negative values on overflow

    printf("Enter voucher code to redeem: ");
    fflush(stdout);
    scanf("%d", &voucher);

        if (voucher > 0) {
            // Calculate total cost with potential for signed integer overflow
            total_cost = voucher * DISCOUNTED;
            printf("Total cost: $%d\n", total_cost);

            if (balance < total_cost) {
                puts("Insufficient funds!");
            } else {
                balance -= total_cost;  // Subtracting a negative value increases balance
                printf("Voucher redeemed! Your new balance is: $%d\n", balance);
            }
        } else {
            puts("Invalid quantity.");
            }
}

void buy_flag() {
    if (balance >= BALANCE_THRESHOLD) {
        FILE *file = fopen("flag.txt", "r");
        if (file == NULL) {
            printf("Error: flag file not found. Please contact an administrator.\n");
            exit(1);
        }

        char flag[128];
        fgets(flag, sizeof(flag), file);
        fclose(file);

        printf("Congratulations! Here is your flag: %s\n", flag);
    } else {
        printf("Insufficient funds. You need $200,000 to buy the flag.\n");
    }
}

void shop() {
    int choice;
    while (1) {
        printf("\nWelcome to the Flag Shop!\n");
        printf("1. View Balance\n2. Redeem Voucher\n3. Buy Original Flag ($200,000)\n4. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                display_balance();
                break;
            case 2:
                redeem_voucher();
                break;
            case 3:
                buy_flag();
                break;
            case 4:
                printf("Exiting shop. Goodbye!\n");
                return;
            default:
                printf("Invalid option. Please try again.\n");
        }
    }
}

int login() {
    char username[16];
    char password[16];

    printf("Enter username: ");
    scanf("%15s", username);
    printf("Enter password: ");
    scanf("%15s", password);

    if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
        printf("Login successful! Welcome, %s.\n", username);
        return 1;
    } else {
        printf("Incorrect username or password.\n");
        return 0;
    }
}

int main() {
    setbuf(stdout, NULL);
    printf("Welcome to the Secure Login Portal.\n");

    if (login()) {
        shop();
    } else {
        printf("Access denied.\n");
    }

    return 0;
}
