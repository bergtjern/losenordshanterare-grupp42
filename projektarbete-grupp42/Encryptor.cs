using System.Security.Cryptography;
using System.Text;

namespace projektarbete_grupp42
{
    public static class Encryptor
    {
        // iterationer för pbkdf2
        private const int Pbkdf2Iterations = 100_000;

        // 32 slumpade bytes sparas i base64 för binärt till text
        public static string CreateSecretKey()
        {
            byte[] secret = new byte[32];
            RandomNumberGenerator.Fill(secret);
            return Convert.ToBase64String(secret);
        }

        // slumpa iv för aes
        public static string CreateIV()
        {
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.GenerateIV();
            return Convert.ToBase64String(aes.IV);
        }

        // master password + (secret från tidigare) som salt i base64 till 32 byte nyckel i vault
        public static byte[] DeriveVaultKey(string masterPassword, string secretKeyBase64)
        {
            byte[] salt = Convert.FromBase64String(secretKeyBase64);
            using Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(
                masterPassword,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32);
        }

        // enkryptera genom json i klartext till base 64 i krypterat valt
        public static string EncryptVault(string plainJson, string masterPassword, string secretKeyBase64, string ivBase64)
        {
            byte[] vaultKey = DeriveVaultKey(masterPassword, secretKeyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            using MemoryStream msOut = new MemoryStream();
            using (CryptoStream cs = new CryptoStream(msOut, encryptor, CryptoStreamMode.Write))
            using (StreamWriter sw = new StreamWriter(cs, Encoding.UTF8))
            {
                sw.Write(plainJson);
            }

            return Convert.ToBase64String(msOut.ToArray());
        }

        // dekryptera genom base64-valvet till klar json
        public static string DecryptVault(string encryptedVaultBase64, string masterPassword, string secretKeyBase64, string ivBase64)
        {
            byte[] vaultKey = DeriveVaultKey(masterPassword, secretKeyBase64);
            byte[] iv = Convert.FromBase64String(ivBase64);
            byte[] cipher = Convert.FromBase64String(encryptedVaultBase64);

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = vaultKey;
            aes.IV = iv;

            using ICryptoTransform decryptor = aes.CreateDecryptor();
            using MemoryStream msIn = new MemoryStream(cipher);
            using CryptoStream cs = new CryptoStream(msIn, decryptor, CryptoStreamMode.Read);
            using StreamReader sr = new StreamReader(cs, Encoding.UTF8);
            return sr.ReadToEnd();
        }
    }
}
