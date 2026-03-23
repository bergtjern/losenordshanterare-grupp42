using System.Security.Cryptography;

namespace projektarbete_grupp42
{
    // för att slumpa lösenord i set (a-z, A-Z, 0-9)

    internal class PasswordGenerator
    {
        private const string Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        public static string GeneratePassword(int length)
        {
            char[] result = new char[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = Chars[RandomNumberGenerator.GetInt32(0, Chars.Length)];
            }
            return new string(result);
        }
    }
}
