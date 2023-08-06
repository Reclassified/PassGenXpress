# PassGenXpress

PassGenXpress is a command-line password generator and manager built in C#. It allows you to generate strong passwords, save them to an encrypted file, and later decrypt and display them when needed. The application uses AES encryption for password storage, ensuring your passwords are securely protected.
_____________________________________________________________________________________________________________________

Features:
Generate and save strong passwords with customizable length and character options.
Store encrypted passwords in a file for safekeeping.
Decrypt and display stored passwords when required.
Utilizes AES encryption to ensure the security of your stored passwords.
User-friendly command-line interface for easy interaction.
_____________________________________________________________________________________________________________________

Usage:
Run the application and choose from the following options:
  Generate and Save Password
  Decrypt and Display Passwords
  Exit
When generating a password, you can specify length and character types (uppercase, lowercase, numbers, special characters).

Encrypted passwords are saved to a file (Pass.pass), and encryption keys are stored separately (key.aes and iv.iv).

When decrypting, the application will read the encrypted passwords from the file and display them in plain text.
_____________________________________________________________________________________________________________________

How to Use:
Clone this repository or download the source code.

Compile and run the PassGenXpress.cs file using a C# compiler (e.g., Visual Studio or the .NET Core CLI).

Follow the on-screen instructions to generate, save, and manage passwords securely.
_____________________________________________________________________________________________________________________

Note:
Make sure to keep the encryption keys (key.aes and iv.iv) in a safe and secure location. Losing these keys will result in the inability to decrypt your stored passwords.
