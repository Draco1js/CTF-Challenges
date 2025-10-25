#!/usr/bin/env python3
"""
Matryoshka Nested Zip Generator
Creates nested password-protected zip files with a hidden flag
"""

import os
import sys
import random
import zipfile
import argparse
import shutil
import string
from pathlib import Path


def load_passwords(rockyou_path, count):
    """Load random passwords from rockyou.txt"""
    if not os.path.exists(rockyou_path):
        print(f"Error: rockyou.txt not found at {rockyou_path}")
        print("Please download rockyou.txt and place it in the project root")
        print("You can find it at: https://github.com/zacheller/rockyou")
        sys.exit(1)
    
    print(f"Loading passwords from {rockyou_path}...")
    passwords = []
    
    try:
        with open(rockyou_path, 'r', encoding='latin-1', errors='ignore') as f:
            all_passwords = [line.strip() for line in f if line.strip()]
        
        # Select random passwords
        if len(all_passwords) < count:
            print(f"Warning: Only {len(all_passwords)} passwords available, requested {count}")
            passwords = all_passwords
        else:
            passwords = random.sample(all_passwords, count)
        
        print(f"Loaded {len(passwords)} passwords")
        return passwords
    except Exception as e:
        print(f"Error reading rockyou.txt: {e}")
        sys.exit(1)


def generate_random_filename(length=12):
    """Generate a random filename with alphanumeric characters"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length)) + '.zip'


def create_random_dummy_file(output_path, min_size_kb=10, max_size_kb=500):
    """Create a random dummy file with random content"""
    size_bytes = random.randint(min_size_kb * 1024, max_size_kb * 1024)
    
    # Generate random binary data
    random_data = os.urandom(size_bytes)
    
    with open(output_path, 'wb') as f:
        f.write(random_data)
    
    return output_path


def embed_flag_in_zip(zip_path, flag_path):
    """Embed flag.jpg into a zip file using steganography (append method)"""
    print(f"  [*] Embedding flag in {os.path.basename(zip_path)}")
    
    # Read the zip file
    with open(zip_path, 'rb') as zf:
        zip_data = zf.read()
    
    # Read the flag image
    with open(flag_path, 'rb') as ff:
        flag_data = ff.read()
    
    # Append flag data to zip (steganography via concatenation)
    # This makes binwalk detect the hidden JPEG
    with open(zip_path, 'wb') as zf:
        zf.write(zip_data)
        zf.write(flag_data)
    
    print(f"  [✓] Flag hidden in {os.path.basename(zip_path)} (use binwalk to extract)")


def create_password_protected_zip(output_zip, files_to_add, password):
    """Create a password-protected zip file"""
    # pyminizip would be ideal but let's use zipfile with encryption
    # Note: zipfile's encryption is weak (ZipCrypto) but works for CTF purposes
    try:
        import pyminizip
        compression_level = 5
        
        # Convert single file to list if needed
        if isinstance(files_to_add, str):
            files_to_add = [files_to_add]
        
        # pyminizip expects lists of source files and destination names
        src_files = files_to_add
        dst_names = [os.path.basename(f) for f in files_to_add]
        
        pyminizip.compress_multiple(src_files, dst_names, output_zip, password, compression_level)
        
    except ImportError:
        # Fallback to zipfile (weaker encryption but works)
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in (files_to_add if isinstance(files_to_add, list) else [files_to_add]):
                arcname = os.path.basename(file_path)
                zf.write(file_path, arcname=arcname)
                # Set password (uses ZipCrypto - weak but functional)
                zf.setpassword(password.encode('utf-8'))
        
        # Apply password to all files
        with zipfile.ZipFile(output_zip, 'r') as zf_read:
            with zipfile.ZipFile(output_zip + '.tmp', 'w', zipfile.ZIP_DEFLATED) as zf_write:
                for item in zf_read.infolist():
                    data = zf_read.read(item.filename)
                    zf_write.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED)
                    zf_write.setpassword(password.encode('utf-8'))
        
        # For better password protection, use pyminizip approach
        # This is a workaround - properly password protecting requires pyminizip
        os.remove(output_zip)
        
        # Use system zip command if available (better password support)
        import subprocess
        
        # Create unprotected zip first
        with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in (files_to_add if isinstance(files_to_add, list) else [files_to_add]):
                arcname = os.path.basename(file_path)
                zf.write(file_path, arcname=arcname)
        
        # Try to use system zip to add password
        try:
            # Create temp unprotected zip
            temp_zip = output_zip + '.tmp'
            os.rename(output_zip, temp_zip)
            
            # Use zip command to create password-protected archive
            result = subprocess.run(
                ['zip', '-P', password, '-j', output_zip] + (files_to_add if isinstance(files_to_add, list) else [files_to_add]),
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0 and os.path.exists(output_zip):
                os.remove(temp_zip)
            else:
                # Fallback to unprotected
                os.rename(temp_zip, output_zip)
                print(f"    Warning: Could not add password protection using system zip")
        except Exception as e:
            print(f"    Warning: System zip command failed: {e}")


def create_nested_zips(num_levels, output_dir, base_image, flag_image, passwords):
    """Create nested zip files with passwords"""
    
    # Special case: if exactly 14 levels, place flag at level 7 (halfway)
    if num_levels == 14:
        flag_level = 6  # Level 7 (index 6) - halfway from both sides as an easter egg
        print(f"\n[*] Creating {num_levels} nested zip files...")
        print(f"[*] Flag will be hidden in level {flag_level + 1} (halfway point)")
        print(f"[*] Passwords will be saved to passwords.txt\n")
    else:
        # For all other cases, choose random level (not innermost or outermost)
        if num_levels > 2:
            flag_level = random.randint(1, num_levels - 1)
        else:
            flag_level = random.randint(0, num_levels - 1)
        
        print(f"\n[*] Creating {num_levels} nested zip files...")
        print(f"[*] Flag will be hidden in level {flag_level + 1}")
        print(f"[*] Passwords will be saved to passwords.txt\n")
    
    # Generate random filenames for each level
    random_filenames = [generate_random_filename() for _ in range(num_levels)]
    
    # Keep track of zip info for the password file
    zip_info = []
    
    # Create the end message text file for the innermost level
    end_message_path = os.path.join(output_dir, "message.txt")
    with open(end_message_path, 'w') as f:
        f.write("You reached the end... was it worth it? Did you miss something along the way?")
    
    # Create zips from innermost to outermost
    current_content = end_message_path
    temp_files = [end_message_path]  # Track temp files to clean up
    
    for level in range(num_levels):
        zip_name = random_filenames[level]
        zip_path = os.path.join(output_dir, zip_name)
        password = passwords[level]
        
        print(f"[{level + 1}/{num_levels}] Creating {zip_name} (password: {password[:20]}{'...' if len(password) > 20 else ''})")
        
        # For the first (innermost) level, only include the message.txt
        # For other levels, include both the nested content and a dummy file
        if level == 0:
            # Innermost level: just the message.txt file
            files_to_add = [current_content]
            print(f"    Adding message.txt")
        else:
            # Other levels: add dummy file along with nested content
            dummy_filename = f"data_{random.randint(1000, 9999)}.dat"
            dummy_path = os.path.join(output_dir, dummy_filename)
            create_random_dummy_file(dummy_path, min_size_kb=50, max_size_kb=800)
            temp_files.append(dummy_path)
            
            print(f"    Adding dummy file: {dummy_filename} ({os.path.getsize(dummy_path) // 1024}KB)")
            files_to_add = [current_content, dummy_path]
        
        # Create the zip file
        create_password_protected_zip(zip_path, files_to_add, password)
        
        # Embed flag in the chosen level
        if level == flag_level:
            embed_flag_in_zip(zip_path, flag_image)
        
        # Store info for passwords.txt
        zip_info.append({
            'level': level + 1,
            'filename': zip_name,
            'password': password,
            'has_flag': level == flag_level,
            'size': 0  # Will be updated after creation
        })
        
        # This zip becomes the content for the next level
        current_content = zip_path
    
    # Update sizes
    for info in zip_info:
        zip_path = os.path.join(output_dir, info['filename'])
        info['size'] = os.path.getsize(zip_path) // 1024  # Size in KB
    
    # Clean up temporary dummy files
    for temp_file in temp_files:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # The final (outermost) zip is the challenge file
    final_zip = os.path.join(output_dir, 'challenge.zip')
    shutil.copy(current_content, final_zip)
    
    # Save passwords to file with filename mapping
    password_file = os.path.join(output_dir, 'passwords.txt')
    with open(password_file, 'w') as pf:
        pf.write("Matryoshka Challenge - Password List\n")
        pf.write("=" * 70 + "\n\n")
        pf.write("🔐 START HERE:\n")
        pf.write(f"challenge.zip | Password: {zip_info[-1]['password']}\n")
        pf.write("\n" + "=" * 70 + "\n\n")
        pf.write("Passwords for nested zips (from outermost to innermost):\n")
        pf.write("-" * 70 + "\n")
        for info in reversed(zip_info):
            flag_marker = " ⭐ CONTAINS FLAG" if info['has_flag'] else ""
            pf.write(f"Level {info['level']:2d}: {info['filename']:20s} | Password: {info['password']}{flag_marker}\n")
            pf.write(f"          Size: {info['size']}KB\n")
        pf.write("\n" + "=" * 70 + "\n")
        pf.write(f"🚩 Flag is hidden in: {random_filenames[flag_level]}\n")
        pf.write(f"   Use: binwalk -e {random_filenames[flag_level]}\n")
        pf.write("=" * 70 + "\n")
    
    print(f"\n[✓] Created {num_levels} nested zips successfully!")
    print(f"[✓] Challenge file: {final_zip}")
    print(f"[✓] Passwords saved to: {password_file}")
    print(f"\n[!] Flag is hidden in {random_filenames[flag_level]}")
    print(f"[!] Extract it with: binwalk -e {os.path.join(output_dir, random_filenames[flag_level])}")
    
    return flag_level, zip_info


def main():
    parser = argparse.ArgumentParser(
        description='Create nested password-protected zip files with hidden flag',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python create_nested_zips.py 5
  python create_nested_zips.py 10 --rockyou ./rockyou.txt
        '''
    )
    
    parser.add_argument(
        'levels',
        type=int,
        help='Number of nested zip levels to create'
    )
    
    parser.add_argument(
        '--rockyou',
        type=str,
        default='rockyou.txt',
        help='Path to rockyou.txt password list (default: ./rockyou.txt)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output directory (default: src/nested_zips)'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if args.levels < 1:
        print("Error: Number of levels must be at least 1")
        sys.exit(1)
    
    # Set up paths
    script_dir = Path(__file__).parent
    base_image = script_dir / 'base.jpeg'
    flag_image = script_dir / 'flag.jpg'
    
    # Check if images exist
    if not base_image.exists():
        print(f"Error: base.jpeg not found at {base_image}")
        sys.exit(1)
    
    if not flag_image.exists():
        print(f"Error: flag.jpg not found at {flag_image}")
        sys.exit(1)
    
    # Set output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = script_dir / 'nested_zips'
    
    # Create output directory
    if output_dir.exists():
        print(f"Warning: Output directory {output_dir} already exists")
        response = input("Do you want to remove it and continue? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            sys.exit(0)
        shutil.rmtree(output_dir)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load passwords
    passwords = load_passwords(args.rockyou, args.levels)
    
    # Create nested zips
    flag_level, zip_info = create_nested_zips(
        args.levels,
        str(output_dir),
        str(base_image),
        str(flag_image),
        passwords
    )
    
    print("\n" + "=" * 70)
    print("Challenge created successfully!")
    print("=" * 70)
    
    # Print all passwords and filenames
    print("\n📋 PASSWORD LIST:")
    print("=" * 70)
    print(f"\n🔐 START HERE:")
    print(f"challenge.zip | Password: {zip_info[-1]['password']}\n")
    print("=" * 70)
    print("Passwords for nested zips (from outermost to innermost):")
    print("-" * 70)
    for info in reversed(zip_info):
        flag_marker = " ⭐ (contains flag)" if info['has_flag'] else ""
        print(f"Level {info['level']:2d}: {info['filename']:20s} | Password: {info['password']}{flag_marker}")
        print(f"          Size: {info['size']}KB")
    print("=" * 70)


if __name__ == '__main__':
    main()

