#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 44
#define FLAGSIZE 64

void reveal_flag() {
    char buf[FLAGSIZE];
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("Flag file is missing. Please contact an administrator.\n");
        exit(0);
    }

    fgets(buf, FLAGSIZE, f);
    fclose(f);

    printf("Oh no! You spilled coffee on the faculty console! Use this cleanup code to resolve it:\n%s\n", buf);
}

void login_as_faculty() {
    char buf[BUFSIZE];
    int logged_in = 0;

    printf("Enter your faculty password: ");
    gets(buf);  // Vulnerable buffer overflow

    char security_code[8];
    printf("Enter your 6-digit faculty security code: ");
    fgets(security_code, sizeof(security_code), stdin);

    printf("\nProcessing...\n");
    if (logged_in != 0) {
        reveal_flag();
    } else {
        printf("Access denied. Security clearance not granted.\n");
    }
}

// Additional Decoy Functions
void view_faculty_records() {
    printf("Accessing faculty records...\n");
    printf("Permission denied. Insufficient clearance level.\n");
}

void reset_password() {
    printf("Resetting password...\n");
    printf("Enter old password: ");
    char old_password[16];
    fgets(old_password, sizeof(old_password), stdin);
    printf("Enter new password: ");
    char new_password[16];
    fgets(new_password, sizeof(new_password), stdin);
    printf("Password reset unsuccessful. Please contact system admin.\n");
}

void view_system_logs() {
    printf("Accessing system logs...\n");
    printf("System logs are classified. Access denied.\n");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    printf("Welcome to the Faculty Security Clearance System.\n");
    printf("Please verify your credentials to proceed.\n");

    int choice;
    while (1) {
        printf("\n1. Attempt Faculty Login\n2. View Faculty Records\n3. Reset Password\n4. View System Logs\n5. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);

        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF);  // Clear buffer

        switch (choice) {
            case 1:
                login_as_faculty();
                break;
            case 2:
                view_faculty_records();
                break;
            case 3:
                reset_password();
                break;
            case 4:
                view_system_logs();
                break;
            case 5:
                printf("Exiting system...\n");
                exit(0);
            default:
                printf("Invalid choice! Try again.\n");
        }
    }
}
