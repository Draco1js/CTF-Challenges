#!/bin/bash

# Compile challenge1.c with specified GCC flags (yaha jis trah binary compile hoti wo command)
gcc -o /app/challenge1 /app/challenge1.c -no-pie -fno-stack-protector -z execstack

# Clean up: remove this entrypoint script after execution
rm -- "$0"

# Start socat to listen on port 1337 and execute challenge1
exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/challenge1",pty,echo=0
