# Matryoshka Challenge - Nested Zip Generator

This script creates nested password-protected zip files with a hidden flag, perfect for CTF challenges.

## Features

- 🎯 Configurable number of nested zip levels
- 🔐 Password-protected using rockyou.txt passwords
- 🎨 Contains base.jpeg in all zips
- 🚩 Hidden flag.jpg embedded in one random zip (detectable with binwalk)
- 📝 Automatically generates password list

## Prerequisites

1. **Download rockyou.txt**

```bash
   wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

2. **Python 3.6+**

## Usage

### Basic Usage

Create 5 nested zip files:

```bash
python create_nested_zips.py 5
```

Specify custom rockyou.txt path:

```bash
python create_nested_zips.py 5 --rockyou /path/to/rockyou.txt
```

Specify custom output directory:

```bash
python create_nested_zips.py 5 --output ./custom_output
```

### Help

```bash
python create_nested_zips.py --help
```

## Output

The script creates a folder `src/nested_zips/` containing:

- `challenge.zip` - The outermost zip file (start here)
- Individual nested zips (Only for reference, they are already within the chal zip)
- `passwords.txt` - List of all passwords and flag location

## How It Works

1. Each zip contains the next level zip file
2. Each zip has a unique password from rockyou.txt
3. One random zip file contains flag.jpg embedded using steganography
4. All zips contain random data to throw off people trying to compare file sizes

## Solving the Challenge

1. Start with `challenge.zip`
2. Extract the password using johntheripper
3. Repeat for each nested level
4. Using binwalk on one of the zip files, you will find a jpeg embedded
5. Extract the jpeg and check the comments for flag

## Notes

- The script uses system `zip` command for password protection (works on macOS/Linux)
- Passwords are randomly selected from rockyou.txt
- The flag location is random each time you run the script
- All output is contained in `src/nested_zips/` to keep src clean
- Take the challenge.zip file and add to base.jpeg to finally put in dist/

## Troubleshooting

**"rockyou.txt not found"**: Download it using the instructions in Prerequisites

**"zip command not found"**: The script requires the `zip` utility (usually pre-installed on macOS/Linux)

**Permission denied**: Make the script executable:

```bash
chmod +x create_nested_zips.py
```
