# Matryoshka

This challenge draws inspiration from Russian nesting dolls, matryoshkas, where each doll hides another inside.

Here is the intended route to solving this challenge:

1. You start with just a single image. Upon closer inspection (for example, using `binwalk`), you'll discover a hidden zip file embedded within the image.

   ```bash
   binwalk image.jpeg
   ```

2. This embedded zip file can be extracted using tools like CyberChef or other CLI tools.

   ```bash
   binwalk -e image.jpeg
   ```
   This will extract any embedded files to a folder.

3. The extracted zip is password-protected. Using John the Ripper and an appropriate wordlist, you can easily crack the password.

   ```bash
   zip2john extracted.zip > hash.txt
   john --wordlist=rockyou.txt hash.txt
   ```
   Replace `extracted.zip` with the actual filename found in the previous step. The password will be printed by John once it's cracked.

4. Inside this zip, you'll find yet another zip alongside a `.dat` file. This `.dat` file is a decoy... just a red herring.

5. You'll notice that each zip contains another nested zip and possibly decoy files, echoing the matryoshka (nesting doll) theme.

6. Reaching the innermost zip, you'll find a text file that says you're out of luck and the flag isn't here, referencing the fact that, in Russian culture, 14 is an unlucky number.

7. A quick Google search (or brute force) shows that 7 is a lucky number in Russian culture.

8. Go back and use binwalk on the 7th zip file (counting from the outermost zip, or check all if unsure) to see if there's another hidden image embedded.

9. Check the comments of the extracted image to find the flag.

   ```bash
   exiftool extracted_flag_image.jpg
   ```
   or, if using `strings`:
   ```bash
   strings extracted_flag_image.jpg | grep flag
   ```

Flag: `flag{nesting_dolls_NAskynRbFY}`