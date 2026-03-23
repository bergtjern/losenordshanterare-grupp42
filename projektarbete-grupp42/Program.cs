namespace projektarbete_grupp42
{
    internal class Program
    {
        // allt körs via kommandorad: dotnet run -- <kommando> [arg...]
        internal static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintManual();
                return;
            }

            // skicka första commandet till lower så det alltid hanterar
            VaultManager vault = new VaultManager();
            string command = args[0].ToLower();

            // onödigt lång, gör kortare...
            switch (command)
            {
                case "init":
                    if (args.Length != 3)
                    {
                        WrongUsage("init <client-file> <server-file>");
                    }
                    else
                    {
                        RunInit(args, vault);
                    }
                    break;

                case "create":
                    if (args.Length != 3)
                    {
                        WrongUsage("create <client-file> <server-file>");
                    }
                    else
                    {
                        RunCreate(args, vault);
                    }
                    break;

                case "get":
                    if (args.Length < 3 || args.Length > 4)
                    {
                        WrongUsage("get <client-file> <server-file> [key]");
                    }
                    else
                    {
                        RunGet(args, vault);
                    }
                    break;

                case "set":
                    if (args.Length < 4 || args.Length > 5)
                    {
                        WrongUsage("set <client-file> <server-file> <key> [-g | --generate]");
                    }
                    else
                    {
                        RunSet(args, vault);
                    }
                    break;

                case "delete":
                    if (args.Length != 4)
                    {
                        WrongUsage("delete <client-file> <server-file> <key>");
                    }
                    else
                    {
                        RunDelete(args, vault);
                    }
                    break;

                case "secret":
                    if (args.Length != 2)
                    {
                        WrongUsage("secret <client-file>");
                    }
                    else
                    {
                        RunSecret(args, vault);
                    }
                    break;

                case "change":
                    if (args.Length != 3)
                    {
                        WrongUsage("change <client-file> <server-file>");
                    }
                    else
                    {
                        RunChange(args, vault);
                    }
                    break;

                case "help":
                    PrintManual();
                    break;

                default:
                    Console.WriteLine($"Error: unknown command '{args[0]}'.");
                    Console.WriteLine("Run the program without arguments to see usage.");
                    break;
            }
        }

        //om felanvändning skicka ut med ett exemepl från switchen
        static void WrongUsage(string example)
        {
            Console.WriteLine("Wrong number of arguments.");
            Console.WriteLine($"Usage: {example}");
        }

        // standard print
        static void PrintManual()
        {
            Console.WriteLine("Grupp 42 - Lösenordshanterare");
            Console.WriteLine();
            Console.WriteLine("init    <client-file> <server-file>");
            Console.WriteLine("create  <client-file> <server-file>");
            Console.WriteLine("get     <client-file> <server-file> [key]");
            Console.WriteLine("set     <client-file> <server-file> <key> [-g | --generate]");
            Console.WriteLine("delete  <client-file> <server-file> <key>");
            Console.WriteLine("secret  <client-file>");
            Console.WriteLine("change  <client-file> <server-file>");
            Console.WriteLine("help    (same as above)");
        }

        //hanterar init
        static void RunInit(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();
            vault.Init(clientPath, serverPath);
        }

        //hanterar create
        static void RunCreate(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();

            Console.Write("Master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            Console.Write("Secret key: ");
            string secretKey = Console.ReadLine() ?? "";

            if (!vault.TryCreateClientFromExistingServer(clientPath, serverPath, masterPassword, secretKey, out string error))
            {
                Console.WriteLine(error);
                return;
            }

            Console.WriteLine($"Client file created: '{clientPath}' (linked to server file).");
        }

        //hanterar get
        static void RunGet(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();

            string propKey = args.Length == 4 ? args[3].Trim() : "";

            Console.WriteLine("Master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                Console.WriteLine("Error: master password cannot be empty.");
                return;
            }

            if (!vault.TryDecryptVaultToDictionary(clientPath, serverPath, masterPassword, out Dictionary<string, string> vaultData, out string error))
            {
                Console.WriteLine(error);
                return;
            }

            if (propKey == "")
            {
                // visa bara nycklar om det tomt
                if (vaultData.Count == 0)
                {
                    Console.WriteLine("(vault is empty — no saved keys)");
                    return;
                }
                foreach (string key in vaultData.Keys)
                {
                    Console.WriteLine(key);
                }
            }
            else
            {
                //kan den här vara null?
                if (!vaultData.TryGetValue(propKey, out string value))
                {
                    Console.WriteLine($"Error: no entry found with key '{propKey}'.");
                    return;
                }
                Console.WriteLine(value);
            }
        }

        //hantera set
        static void RunSet(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();
            string propKey = args[3].Trim();

            bool generate = false;
            if (args.Length == 5)
            {
                string doGenerate = args[4].Trim();
                if (doGenerate == "-g" || doGenerate == "--generate")
                {
                    generate = true;
                }
                else
                {
                    Console.WriteLine("Error: unknown flag. Use -g or --generate to generate password.");
                    return;
                }
            }

            Console.Write("Master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                Console.WriteLine("Error: master password cannot be empty.");
                return;
            }

            string passwordToStore;
            if (generate)
            {
                passwordToStore = PasswordGenerator.GeneratePassword(20);
                Console.WriteLine($"Generated password (20 chars): {passwordToStore}");
            }
            else
            {
                Console.Write($"Value to save for '{propKey}': ");
                passwordToStore = Console.ReadLine() ?? "";
            }

            if (!vault.TrySetPasswordEntry(clientPath, serverPath, masterPassword, propKey, passwordToStore, out string error))
            {
                Console.WriteLine(error);
                return;
            }

            Console.WriteLine($"Saved under key '{propKey}'.");
        }

        //hantera delete
        static void RunDelete(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();
            string propKey = args[3].Trim();

            Console.Write("Master password: ");
            string masterPassword = Console.ReadLine() ?? "";

            if (string.IsNullOrWhiteSpace(masterPassword))
            {
                Console.WriteLine("Master password cannot be empty.");
                return;
            }

            if (!vault.TryDeletePasswordEntry(clientPath, serverPath, masterPassword, propKey, out string error))
            {
                Console.WriteLine(error);
                return;
            }

            Console.WriteLine($"Key '{propKey}' is deleted.");
        }

        //hantera secret
        static void RunSecret(string[] args, VaultManager vault)
        {
            vault.Secret(args[1].Trim());
        }

        //hantera change
        static void RunChange(string[] args, VaultManager vault)
        {
            string clientPath = args[1].Trim();
            string serverPath = args[2].Trim();

            Console.Write("Current master password: ");
            string currentMaster = Console.ReadLine() ?? "";

            Console.Write("New master password: ");
            string newMaster = Console.ReadLine() ?? "";

            if (!vault.TryChangeMasterPassword(clientPath, serverPath, currentMaster, newMaster, out string error))
            {
                Console.WriteLine(error);
                return;
            }

            Console.WriteLine("Password changed.");
        }
    }
}