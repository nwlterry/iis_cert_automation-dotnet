using System.Diagnostics;

namespace IisCertAutomation.Windows;

public static class CommandRunner
{
    public static int Run(string fileName, params string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(fileName + " is only invoked on Windows.");
        }

        var start = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args)
        {
            start.ArgumentList.Add(arg);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start " + fileName);
        process.WaitForExit();
        return process.ExitCode;
    }

    public static void TightenAcl(string path)
    {
        var code = Run(
            "icacls.exe",
            path,
            "/inheritance:r",
            "/grant:r",
            @"NT AUTHORITY\SYSTEM:(F)",
            @"BUILTIN\Administrators:(F)");
        if (code != 0)
        {
            throw new InvalidOperationException("Failed to restrict the ACL. Stopping so secret material is not left broadly readable.");
        }
    }
}
