using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections.Generic;

namespace SecureAuthSystem
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("Secure Authentication System");
                Console.WriteLine("1. Register");
                Console.WriteLine("2. Login");
                Console.WriteLine("3. Reset Password");
                Console.WriteLine("4. Exit");
                Console.Write("Select an option: ");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        RegisterUser();
                        break;
                    case "2":
                        User loggedInUser = Login();
                        if (loggedInUser != null)
                        {
                            UserMenu(loggedInUser);
                        }
                        break;
                    case "3":
                        ResetPassword();
                        break;
                    case "4":
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine("Invalid option. Press any key to continue...");
                        Console.ReadKey();
                        break;
                }
            }
        }

        static void RegisterUser()
        {
            Console.Clear();
            Console.WriteLine("User Registration");

            Console.Write("Enter name: ");
            string name = Console.ReadLine();

            Console.Write("Enter email: ");
            string email = Console.ReadLine().ToLower();

            // Check if email already exists
            if (File.Exists("users.txt"))
            {
                string[] users = File.ReadAllLines("users.txt");
                foreach (string user in users)
                {
                    string[] parts = user.Split('|');
                    if (parts.Length > 1 && parts[1] == email)
                    {
                        Console.WriteLine("Email already registered. Press any key to continue...");
                        Console.ReadKey();
                        return;
                    }
                }
            }

            Console.Write("Enter password: ");
            string password = Console.ReadLine();

            // Generate RSA key pair
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    string publicKey = rsa.ToXmlString(false);
                    string privateKey = rsa.ToXmlString(true);

                    // Hash the password
                    string hashedPassword = HashPassword(password);

                    // Save user data
                    string userData = $"{name}|{email}|{hashedPassword}|{publicKey}|{privateKey}";

                    File.AppendAllText("users.txt", userData + Environment.NewLine);

                    // Create user's encrypted text file
                    File.Create($"{email}_encrypted.txt").Close();

                    Console.WriteLine("Registration successful! Press any key to continue...");
                    Console.ReadKey();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        static User Login()
        {
            Console.Clear();
            Console.WriteLine("User Login");

            Console.Write("Enter email: ");
            string email = Console.ReadLine().ToLower();

            Console.Write("Enter password: ");
            string password = Console.ReadLine();

            if (File.Exists("users.txt"))
            {
                string[] users = File.ReadAllLines("users.txt");
                foreach (string user in users)
                {
                    string[] parts = user.Split('|');
                    if (parts.Length >= 3 && parts[1] == email)
                    {
                        string storedHash = parts[2];
                        string inputHash = HashPassword(password);

                        if (storedHash == inputHash)
                        {
                            Console.WriteLine("Login successful! Press any key to continue...");
                            Console.ReadKey();

                            // Return user object
                            return new User
                            {
                                Name = parts[0],
                                Email = parts[1],
                                PasswordHash = parts[2],
                                PublicKey = parts.Length > 3 ? parts[3] : "",
                                PrivateKey = parts.Length > 4 ? parts[4] : ""
                            };
                        }
                    }
                }
            }

            Console.WriteLine("Invalid email or password. Press any key to continue...");
            Console.ReadKey();
            return null;
        }

        static void ResetPassword()
        {
            Console.Clear();
            Console.WriteLine("Password Reset");

            Console.Write("Enter your email: ");
            string email = Console.ReadLine().ToLower();

            if (File.Exists("users.txt"))
            {
                string[] users = File.ReadAllLines("users.txt");
                bool found = false;

                for (int i = 0; i < users.Length; i++)
                {
                    string[] parts = users[i].Split('|');
                    if (parts.Length >= 3 && parts[1] == email)
                    {
                        found = true;

                        Console.Write("Enter new password: ");
                        string newPassword = Console.ReadLine();

                        string newHash = HashPassword(newPassword);

                        // Reconstruct user data with new password
                        string newUserData = $"{parts[0]}|{parts[1]}|{newHash}";

                        // Add keys if they exist
                        if (parts.Length > 3) newUserData += $"|{parts[3]}";
                        if (parts.Length > 4) newUserData += $"|{parts[4]}";

                        users[i] = newUserData;

                        File.WriteAllLines("users.txt", users);
                        Console.WriteLine("Password reset successful! Press any key to continue...");
                        break;
                    }
                }

                if (!found)
                {
                    Console.WriteLine("Email not found. Press any key to continue...");
                }
            }
            else
            {
                Console.WriteLine("No users registered yet. Press any key to continue...");
            }

            Console.ReadKey();
        }

        static void UserMenu(User user)
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine($"Welcome, {user.Name}!");
                Console.WriteLine("1. Encrypt Text");
                Console.WriteLine("2. Decrypt Text");
                Console.WriteLine("3. Change Password");
                Console.WriteLine("4. Logout");
                Console.Write("Select an option: ");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        EncryptText(user);
                        break;
                    case "2":
                        DecryptText(user);
                        break;
                    case "3":
                        ChangePassword(user);
                        break;
                    case "4":
                        return;
                    default:
                        Console.WriteLine("Invalid option. Press any key to continue...");
                        Console.ReadKey();
                        break;
                }
            }
        }

        static void EncryptText(User user)
        {
            Console.Clear();
            Console.WriteLine("Text Encryption");

            Console.Write("Enter text to encrypt: ");
            string textToEncrypt = Console.ReadLine();

            if (string.IsNullOrEmpty(textToEncrypt))
            {
                Console.WriteLine("No text entered. Press any key to continue...");
                Console.ReadKey();
                return;
            }

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    rsa.FromXmlString(user.PublicKey);

                    byte[] dataToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, false);

                    string encryptedHex = BitConverter.ToString(encryptedData).Replace("-", "");

                    // Save encrypted text to user's file
                    File.AppendAllText($"{user.Email}_encrypted.txt", encryptedHex + Environment.NewLine);

                    Console.WriteLine("Text encrypted and saved successfully!");
                    Console.WriteLine($"Encrypted: {encryptedHex}");
                    Console.WriteLine("Press any key to continue...");
                    Console.ReadKey();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        static void DecryptText(User user)
        {
            Console.Clear();
            Console.WriteLine("Text Decryption");

            string userFile = $"{user.Email}_encrypted.txt";

            if (!File.Exists(userFile) || new FileInfo(userFile).Length == 0)
            {
                Console.WriteLine("No encrypted texts found. Press any key to continue...");
                Console.ReadKey();
                return;
            }

            string[] encryptedTexts = File.ReadAllLines(userFile);

            if (encryptedTexts.Length == 0)
            {
                Console.WriteLine("No encrypted texts found. Press any key to continue...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Select text to decrypt:");
            for (int i = 0; i < encryptedTexts.Length; i++)
            {
                Console.WriteLine($"{i + 1}. {encryptedTexts[i]}");
            }

            Console.Write("Enter the number of the text to decrypt: ");
            if (int.TryParse(Console.ReadLine(), out int choice) && choice > 0 && choice <= encryptedTexts.Length)
            {
                string selectedEncryptedHex = encryptedTexts[choice - 1];

                try
                {
                    byte[] encryptedData = Enumerable.Range(0, selectedEncryptedHex.Length)
                        .Where(x => x % 2 == 0)
                        .Select(x => Convert.ToByte(selectedEncryptedHex.Substring(x, 2), 16))
                        .ToArray();

                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                    {
                        try
                        {
                            rsa.FromXmlString(user.PrivateKey);

                            byte[] decryptedData = rsa.Decrypt(encryptedData, false);
                            string decryptedText = Encoding.UTF8.GetString(decryptedData);

                            Console.WriteLine($"Decrypted text: {decryptedText}");
                        }
                        finally
                        {
                            rsa.PersistKeyInCsp = false;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Decryption failed: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Invalid selection.");
            }

            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();
        }

        static void ChangePassword(User user)
        {
            Console.Clear();
            Console.WriteLine("Change Password");

            Console.Write("Enter current password: ");
            string currentPassword = Console.ReadLine();

            string currentHash = HashPassword(currentPassword);

            if (currentHash != user.PasswordHash)
            {
                Console.WriteLine("Incorrect current password. Press any key to continue...");
                Console.ReadKey();
                return;
            }

            Console.Write("Enter new password: ");
            string newPassword = Console.ReadLine();

            string newHash = HashPassword(newPassword);

            // Update user data in file
            string[] users = File.ReadAllLines("users.txt");
            for (int i = 0; i < users.Length; i++)
            {
                string[] parts = users[i].Split('|');
                if (parts.Length >= 3 && parts[1] == user.Email)
                {
                    // Reconstruct user data with new password
                    string newUserData = $"{parts[0]}|{parts[1]}|{newHash}";

                    // Add keys if they exist
                    if (parts.Length > 3) newUserData += $"|{parts[3]}";
                    if (parts.Length > 4) newUserData += $"|{parts[4]}";

                    users[i] = newUserData;
                    break;
                }
            }

            File.WriteAllLines("users.txt", users);

            // Update the current user object
            user.PasswordHash = newHash;

            Console.WriteLine("Password changed successfully! Press any key to continue...");
            Console.ReadKey();
        }

        static string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }
    }

    class User
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }
}