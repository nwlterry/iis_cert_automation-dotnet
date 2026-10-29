namespace IisCertAutomation.Commands;

public static class Cli
{
    public static void RejectPasswordOnCommandLine(string[] args)
    {
        foreach (var arg in args)
        {
            var name = arg.Split('=', 2)[0];
            if (name.Equals("--password", StringComparison.OrdinalIgnoreCase)
                || name.Equals("-password", StringComparison.OrdinalIgnoreCase)
                || name.Equals("/password", StringComparison.OrdinalIgnoreCase)
                || name.Equals("-p", StringComparison.OrdinalIgnoreCase)
                || name.Equals("/p", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Do not pass the PFX password on the command line. The setup command prompts for it.");
            }
        }
    }

    public static string? Option(string[] args, string name)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return args[i + 1];
            }

            var prefix = name + "=";
            if (args[i].StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return args[i][prefix.Length..];
            }
        }

        return null;
    }

    public static bool Has(string[] args, string name)
        => args.Any(arg => arg.Equals(name, StringComparison.OrdinalIgnoreCase));

    public static string ReadConsoleSecret()
    {
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException("Refusing to read a password from redirected input.");
        }

        Console.Write("PFX password: ");
        var chars = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (chars.Count > 0)
                {
                    chars.RemoveAt(chars.Count - 1);
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                chars.Add(key.KeyChar);
            }
        }

        Console.WriteLine();
        var secret = new string(chars.ToArray());
        chars.Clear();
        if (secret.Length == 0)
        {
            throw new InvalidOperationException("PFX password is required.");
        }

        return secret;
    }
}
