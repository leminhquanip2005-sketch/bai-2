using System;
using System.Text;
using System.Security.Cryptography;

namespace RSADemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            // a. Tạo cặp khóa
            using (RSA aliceRSA = RSA.Create(2048))
            using (RSA bobRSA = RSA.Create(2048))
            {
                Console.WriteLine("=== A. TAO CAP KHOA ===");
                Console.WriteLine("Alice & Bob da khoi tao cap khoa thanh cong.");

                string plainText = "Tai lieu mat cua Alice gui cho Bob.";
                Console.WriteLine($"\nVan ban goc: {plainText}");

                // b. Mã hóa và giải mã (Alice -> Bob)
                Console.WriteLine("\n=== B. MA HOA VA GIAI HOA (BOB DOC) ===");
                byte[] encryptedData = EncryptText(plainText, bobRSA);
                Console.WriteLine("Da ma hoa du lieu thanh cong.");

                string decryptedText = DecryptText(encryptedData, bobRSA);
                Console.WriteLine($"Bob giai ma duoc: {decryptedText}");

                // c. Ký số xác nhận bản quyền (Alice)
                Console.WriteLine("\n=== C. XAC NHAN BAN QUYEN (KY SO ALICE) ===");
                byte[] signature = SignData(plainText, aliceRSA);

                bool isVerified = VerifyData(plainText, signature, aliceRSA);
                Console.WriteLine($"Kiem tra chu ky cua Alice (Chinh xac): {isVerified}");

                // Thử nghiệm giả mạo
                string fakeText = plainText + " [Da bi sua doi]";
                bool isFakeVerified = VerifyData(fakeText, signature, aliceRSA);
                Console.WriteLine($"Kiem tra tai lieu da bi sua doi: {isFakeVerified}");
            }
            Console.ReadKey();
        }

        public static byte[] EncryptText(string plainText, RSA rsa)
        {
            return rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
        }

        public static string DecryptText(byte[] encryptedData, RSA rsa)
        {
            return Encoding.UTF8.GetString(rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256));
        }

        public static byte[] SignData(string plainText, RSA rsa)
        {
            return rsa.SignData(Encoding.UTF8.GetBytes(plainText), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static bool VerifyData(string plainText, byte[] signature, RSA rsa)
        {
            return rsa.VerifyData(Encoding.UTF8.GetBytes(plainText), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}