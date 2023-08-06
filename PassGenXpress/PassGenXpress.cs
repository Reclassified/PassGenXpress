using System.Security.Cryptography;
using Aes = System.Security.Cryptography.Aes;

namespace PassGenXpress
{
    internal class PassGenXpress
    {
        private static readonly byte[] Key;
        private static readonly byte[] IV;

        static PassGenXpress()
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.KeySize = 256;
            Key = aesAlg.Key;
            IV = aesAlg.IV;
        }

        static void Main()
        {
            MainRunner();
        }

        static void MainRunner()
        {
            Console.Title = "PassGenXpress by MasterBlastr";
            Console.WriteLine("Welcome to PassGenXpress by MasterBlastr");

            while (true)
            {
                Console.Clear(); // Clear the console before displaying the menu

                Console.WriteLine("1. Generate and Save Password");
                Console.WriteLine("2. Decrypt and Display Passwords");
                Console.WriteLine("3. Exit");

                Console.Write("Select an option: ");
                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        GenerateAndSavePassword();
                        break;
                    case "2":
                        DecryptAndDisplayPasswords();
                        break;
                    case "3":
                        return;
                    default:
                        Console.WriteLine("Invalid choice. Please select a valid option.");
                        break;
                }
            }
        }

        static void GenerateAndSavePassword()
        {
            Console.Clear(); // Clear the console before generating and saving a password

            int passwordLength = GetPasswordLength();
            bool includeUppercase = GetCharacterChoice("uppercase letters");
            bool includeLowercase = GetCharacterChoice("lowercase letters");
            bool includeNumbers = GetCharacterChoice("numbers");
            bool includeSpecialChars = GetCharacterChoice("special characters");

            string generatedPassword = GeneratePassword(passwordLength, includeUppercase, includeLowercase, includeNumbers, includeSpecialChars);
            Console.WriteLine("Generated Password: " + generatedPassword);

            SavePasswordToFile(generatedPassword);

            Console.WriteLine("\nPress Enter to continue...");
            Console.ReadLine(); // Wait for user to press Enter before clearing the console again
        }

        static void DecryptAndDisplayPasswords()
        {
            Console.Clear(); // Clear the console before decrypting and displaying passwords

            string currentDirectory = Directory.GetCurrentDirectory();
            string encryptedFilePath = Path.Combine(currentDirectory, "Pass.pass");
            string keyFilePath = Path.Combine(currentDirectory, "key.aes");
            string ivFilePath = Path.Combine(currentDirectory, "iv.iv");

            try
            {
                string[] encryptedPasswords = File.ReadAllLines(encryptedFilePath);
                byte[] key = File.ReadAllBytes(keyFilePath);
                byte[] iv = File.ReadAllBytes(ivFilePath);

                Console.WriteLine("Decrypted Passwords:\n");

                for (int i = 0; i < encryptedPasswords.Length; i++)
                {
                    string encryptedPassword = encryptedPasswords[i];
                    string decryptedPassword = DecryptPassword(Convert.FromBase64String(encryptedPassword), key, iv);

                    Console.WriteLine($"Password {i + 1}: {decryptedPassword}");
                }

                Console.WriteLine("\nPress Enter to continue...");
                Console.ReadLine(); // Wait for user to press Enter before clearing the console again
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
                Console.WriteLine("\nPress Enter to continue...");
                Console.ReadLine(); // Wait for user to press Enter before clearing the console again
            }
        }

        static int GetPasswordLength()
        {
            int minLength = 6;
            int maxLength = 30;

            while (true)
            {
                Console.Write($"Enter password length ({minLength}-{maxLength}): ");
                if (int.TryParse(Console.ReadLine(), out int length))
                {
                    if (length >= minLength && length <= maxLength)
                    {
                        return length;
                    }
                    else
                    {
                        Console.WriteLine($"Password length must be between {minLength} and {maxLength} characters.");
                    }
                }
                else
                {
                    Console.WriteLine("Invalid input. Please enter a valid number.");
                }
            }
        }

        static bool GetCharacterChoice(string characterType)
        {
            while (true)
            {
                Console.Write($"Include {characterType}? (Y/N): ");
                string input = Console.ReadLine().Trim().ToLower();

                if (input == "y")
                {
                    return true;
                }
                else if (input == "n")
                {
                    return false;
                }
                else
                {
                    Console.WriteLine("Invalid input. Please enter 'Y' for Yes or 'N' for No.");
                }
            }
        }

        static string GeneratePassword(int length, bool includeUppercase, bool includeLowercase, bool includeNumbers, bool includeSpecialChars)
        {
            const string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
            const string numberChars = "0123456789";
            const string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";

            string validChars = "";

            if (includeUppercase)
            {
                validChars += uppercaseChars;
            }
            if (includeLowercase)
            {
                validChars += lowercaseChars;
            }
            if (includeNumbers)
            {
                validChars += numberChars;
            }
            if (includeSpecialChars)
            {
                validChars += specialChars;
            }

            if (validChars == "")
            {
                Console.WriteLine("No character type selected. Generating password with lowercase letters and numbers.");
                validChars = lowercaseChars + numberChars;
            }

            Random random = new Random();
            char[] password = new char[length];

            for (int i = 0; i < length; i++)
            {
                password[i] = validChars[random.Next(validChars.Length)];
            }

            return new string(password);
        }

        static void SavePasswordToFile(string password)
        {
            string fileName = "Pass.pass";

            try
            {
                string encryptedPassword = EncryptPassword(password);

                using (StreamWriter writer = File.AppendText(fileName))
                {
                    writer.WriteLine(encryptedPassword);
                    Console.WriteLine("Encrypted password saved to the file.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while saving the password: {ex.Message}");
            }
        }

        static string EncryptPassword(string password)
        {
            string keyFilePath = "key.aes";
            string ivFilePath = "iv.iv";

            if (!File.Exists(keyFilePath) || !File.Exists(ivFilePath))
            {
                using Aes aesAlg = Aes.Create();
                aesAlg.KeySize = 256;
                aesAlg.GenerateKey();
                aesAlg.GenerateIV();

                File.WriteAllBytes(keyFilePath, aesAlg.Key);
                File.WriteAllBytes(ivFilePath, aesAlg.IV);
            }

            byte[] encryptedBytes;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = File.ReadAllBytes(keyFilePath);
                aesAlg.IV = File.ReadAllBytes(ivFilePath);

                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
                {
                    using MemoryStream msEncrypt = new MemoryStream();
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(password);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encryptedBytes);
        }

        static string DecryptPassword(byte[] encryptedBytes, byte[] key, byte[] iv)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
            {
                using MemoryStream msDecrypt = new MemoryStream(encryptedBytes);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using StreamReader srDecrypt = new StreamReader(csDecrypt);
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}
