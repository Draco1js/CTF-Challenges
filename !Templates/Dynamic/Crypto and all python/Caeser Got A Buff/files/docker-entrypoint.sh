#!/bin/bash
rm -- "$0"
exec socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"python3 /app/main.py",pty,echo=0