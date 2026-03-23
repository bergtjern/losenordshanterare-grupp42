using System.Security.Cryptography;
using System.Text.Json;

namespace projektarbete_grupp42
{
    // hanterar valvet och kopplas till encryptorn
    // vet inte om json exc behövs men la till ändå, men bör alltid vara json
    internal class VaultManager
    {
        //gör init, hantera tomt, skapar nycker, client och server
        public void Init(string clientPath, string serverPath)
        {
            if (string.IsNullOrWhiteSpace(clientPath) || string.IsNullOrWhiteSpace(serverPath))
            {
                Console.WriteLine("Error: Both client file and server file must be specified.");
                return;
            }

            Console.Write("Master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                Console.WriteLine("Master password cannot be empty.");
                return;
            }

            try
            {
                string secretKey = Encryptor.CreateSecretKey();
                string iv = Encryptor.CreateIV();

                string vaultJson = JsonSerializer.Serialize(new Dictionary<string, string>());
                string encryptedVault = Encryptor.EncryptVault(vaultJson, masterPassword, secretKey, iv);

                var clientData = new ClientConfig { Secret = secretKey };
                if (!TrySaveClientConfig(clientPath, clientData, out string clientErr))
                {
                    Console.WriteLine(clientErr);
                    return;
                }

                var serverData = new ServerConfig
                {
                    IV = iv,
                    EncryptedVault = encryptedVault
                };
                if (!TrySaveServerConfig(serverPath, serverData, out string serverErr))
                {
                    Console.WriteLine(serverErr);
                    return;
                }

                Console.WriteLine();
                Console.WriteLine("Your secret key (save it somewhere safe):");
                Console.WriteLine(secretKey);
                Console.WriteLine();
                Console.WriteLine($"Init complete. Client saved as '{clientPath}', server as '{serverPath}'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        // försöker läsa hela client filen som en text för att ha datan
        private bool TryReadClientFile(string clientPath, out string json, out string error)
        {
            json = "";
            error = "";

            try
            {
                json = File.ReadAllText(clientPath);
                return true;
            }
            catch (Exception ex)
            {
                error = $"Could not read client file: {ex.Message}";
                return false;
            }
        }

        // försöker läsa hela server filen som en text för att hantera data
        private bool TryReadServerFile(string serverPath, out string json, out string error)
        {
            json = "";
            error = "";

            try
            {
                json = File.ReadAllText(serverPath);
                return true;
            }
            catch (Exception ex)
            {
                error = $"Could not read server file: {ex.Message}";
                return false;
            }
        }

        // konverterar json texten i clientconfig till ett objekt som vi kan printa key med
        private bool TryParseClientConfig(string json, out ClientConfig config, out string error)
        {
            config = new ClientConfig();
            error = "";

            try
            {
                ClientConfig c = JsonSerializer.Deserialize<ClientConfig>(json)!;

                if (c == null || string.IsNullOrWhiteSpace(c.Secret))
                {
                    error = "Client file is missing a valid secret.";
                    return false;
                }
                config = c;
                return true;
            }
            catch (JsonException ex)
            {
                error = $"Client file is not valid JSON: {ex.Message}";
                return false;
            }
        }

        // konverterar json filen i serverconfig för att komma åt iv och den krypterade nyckeln
        private bool TryParseServerConfig(string json, out ServerConfig config, out string error)
        {
            config = new ServerConfig();
            error = "";

            try
            {
                ServerConfig s = JsonSerializer.Deserialize<ServerConfig>(json)!;

                if (s == null || string.IsNullOrWhiteSpace(s.IV) || string.IsNullOrWhiteSpace(s.EncryptedVault))
                {
                    error = "Server file is missing IV or encrypted vault.";
                    return false;
                }
                config = s;
                return true;
            }
            catch (JsonException ex)
            {
                error = $"Server file is not valid JSON: {ex.Message}";
                return false;
            }
        }

        // hämtar ut secret key från clientconfig
        public bool TryLoadSecretKey(string clientPath, out string secretKeyBase64, out string error)
        {
            secretKeyBase64 = "";
            if (!TryReadClientFile(clientPath, out string json, out error))
                return false;
            if (!TryParseClientConfig(json, out ClientConfig client, out error))
                return false;
            secretKeyBase64 = client.Secret;
            return true;
        }

        // hämtar ut iv och försöker läsa vaultet från serverfilen
        public bool TryLoadEncryptedVaultFromServer(string serverPath, out string ivBase64, out string encryptedVaultBase64, out string error)
        {
            ivBase64 = "";
            encryptedVaultBase64 = "";
            if (!TryReadServerFile(serverPath, out string json, out error))
                return false;
            if (!TryParseServerConfig(json, out ServerConfig server, out error))
                return false;
            ivBase64 = server.IV;
            encryptedVaultBase64 = server.EncryptedVault;
            return true;
        }

        // använder nycklarna och lösenordet för att skapa ett dictionary så det kan visas i minnet och öppna valvet
        public bool TryDecryptVaultToDictionary(string clientPath, string serverPath, string masterPassword, out Dictionary<string, string> vault, out string error)
        {
            vault = new Dictionary<string, string>();
            error = "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                error = "Master password cannot be empty.";
                return false;
            }

            if (!TryLoadSecretKey(clientPath, out string secret, out error))
                return false;
            if (!TryLoadEncryptedVaultFromServer(serverPath, out string iv, out string encrypted, out error))
                return false;

            try
            {
                string plainJson = Encryptor.DecryptVault(encrypted, masterPassword, secret, iv);
                Dictionary<string, string> dict = JsonSerializer.Deserialize<Dictionary<string, string>>(plainJson)!;
                vault = dict ?? new Dictionary<string, string>();
                return true;
            }
            catch (CryptographicException)
            {
                error = "Could not decrypt vault (wrong master password or corrupted data).";
                return false;
            }
            catch (JsonException ex)
            {
                error = $"Vault decrypted but content is invalid JSON: {ex.Message}";
                return false;
            }
        }

        // verifiera master pass och secret stämmer och försöker skapa ny client (onödigt lång)
        public bool TryCreateClientFromExistingServer(string clientPath, string serverPath, string masterPassword, string secretKeyBase64, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                error = "Master password cannot be empty.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(secretKeyBase64))
            {
                error = "Secret key cannot be empty.";
                return false;
            }

            secretKeyBase64 = secretKeyBase64.Trim();

            if (!TryLoadEncryptedVaultFromServer(serverPath, out string iv, out string encrypted, out error))
                return false;

            try
            {
                string plainJson = Encryptor.DecryptVault(encrypted, masterPassword, secretKeyBase64, iv);
                JsonSerializer.Deserialize<Dictionary<string, string>>(plainJson);
            }
            catch (CryptographicException)
            {
                error = "Could not open vault — wrong master password or wrong secret key,";
                return false;
            }
            catch (JsonException ex)
            {
                error = $"Vault cannot be read as JSON: {ex.Message}";
                return false;
            }

            var clientData = new ClientConfig { Secret = secretKeyBase64 };
            return TrySaveClientConfig(clientPath, clientData, out error);
        }

        // sparar ett nytt lösenord eller uppdaterar i dictionariet
        public bool TrySetPasswordEntry(string clientPath, string serverPath, string masterPassword, string propKey, string value, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(propKey))
            {
                error = "Key cannot be empty.";
                return false;
            }

            if (!TryDecryptVaultToDictionary(clientPath, serverPath, masterPassword, out Dictionary<string, string> vault, out error))
                return false;

            vault[propKey] = value;
            return TryEncryptAndSaveVault(clientPath, serverPath, masterPassword, vault, out error);
        }

        // tar bort en nyckel från dictionary
        public bool TryDeletePasswordEntry(string clientPath, string serverPath, string masterPassword, string propKey, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(propKey))
            {
                error = "Key cannot be empty.";
                return false;
            }

            if (!TryDecryptVaultToDictionary(clientPath, serverPath, masterPassword, out Dictionary<string, string> vault, out error))
                return false;

            if (!vault.Remove(propKey))
            {
                error = $"There is no entry with key '{propKey}'.";
                return false;
            }

            return TryEncryptAndSaveVault(clientPath, serverPath, masterPassword, vault, out error);
        }

        public bool TryChangeMasterPassword(string clientPath, string serverPath, string currentMasterPassword, string newMasterPassword, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(newMasterPassword))
            {
                error = "New master password cannot be empty.";
                return false;
            }

            if (!TryDecryptVaultToDictionary(clientPath, serverPath, currentMasterPassword, out Dictionary<string, string> vault, out error))
                return false;

            return TryEncryptAndSaveVault(clientPath, serverPath, newMasterPassword, vault, out error);
        }

        public bool TryEncryptAndSaveVault(string clientPath, string serverPath, string masterPassword, Dictionary<string, string> vault, out string error)
        {
            error = "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                error = "Master password cannot be empty.";
                return false;
            }

            if (!TryLoadSecretKey(clientPath, out string secret, out error))
                return false;
            if (!TryLoadEncryptedVaultFromServer(serverPath, out string iv, out _, out error))
                return false;

            try
            {
                string vaultJson = JsonSerializer.Serialize(vault);
                string encryptedVault = Encryptor.EncryptVault(vaultJson, masterPassword, secret, iv);

                var serverData = new ServerConfig
                {
                    IV = iv,
                    EncryptedVault = encryptedVault
                };

                return TrySaveServerConfig(serverPath, serverData, out error);
            }
            catch (Exception ex)
            {
                error = $"Error during encryption or saving: {ex.Message}";
                return false;
            }
        }

        public bool TrySaveClientConfig(string clientPath, ClientConfig config, out string error)
        {
            error = "";
            try
            {
                string json = JsonSerializer.Serialize(config);
                File.WriteAllText(clientPath, json);
                return true;
            }
            catch (Exception ex)
            {
                error = $"Could not write client file: {ex.Message}";
                return false;
            }
        }

        //hjälpmetod för att testa att server file kan skapas
        public bool TrySaveServerConfig(string serverPath, ServerConfig config, out string error)
        {
            error = "";
            try
            {
                string json = JsonSerializer.Serialize(config);
                File.WriteAllText(serverPath, json);
                return true;
            }
            catch (Exception ex)
            {
                error = $"Could not write server file: {ex.Message}";
                return false;
            }
        }

        // läser ut hemliga nyckeln från client
        public void Secret(string clientPath)
        {
            if (!TryLoadSecretKey(clientPath, out string secret, out string error))
            {
                Console.WriteLine(error);
                return;
            }
            Console.WriteLine(secret);
        }
    }
}