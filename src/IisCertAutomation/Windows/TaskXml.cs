using System.Xml.Linq;
using IisCertAutomation.Security;

namespace IisCertAutomation.Windows;

public static class TaskXml
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static string Build(string taskName, string executable, string arguments, string description, bool eventTrigger, bool hourly = false)
    {
        PathGuard.RequireSafeTaskName(taskName);
        PathGuard.RequireSafePath(executable);
        if (arguments.IndexOfAny(['\r', '\n', '\0']) >= 0)
        {
            throw new InvalidOperationException("Refusing task arguments with control characters.");
        }

        var triggers = new XElement(Ns + "Triggers");
        if (eventTrigger)
        {
            triggers.Add(new XElement(Ns + "EventTrigger",
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "Subscription", EventQuery())));
        }

        var boot = new XElement(Ns + "BootTrigger", new XElement(Ns + "Enabled", "true"));
        if (hourly)
        {
            boot.Add(new XElement(Ns + "Repetition",
                new XElement(Ns + "Interval", "PT1H"),
                new XElement(Ns + "StopAtDurationEnd", "false")));
        }

        triggers.Add(boot);

        var doc = new XDocument(
            new XElement(Ns + "Task",
                new XAttribute("version", "1.2"),
                new XElement(Ns + "RegistrationInfo", new XElement(Ns + "Description", description)),
                triggers,
                new XElement(Ns + "Principals",
                    new XElement(Ns + "Principal",
                        new XAttribute("id", "System"),
                        new XElement(Ns + "UserId", "S-1-5-18"),
                        new XElement(Ns + "RunLevel", "HighestAvailable"))),
                new XElement(Ns + "Settings",
                    new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                    new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                    new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                    new XElement(Ns + "AllowHardTerminate", "true"),
                    new XElement(Ns + "StartWhenAvailable", "true"),
                    new XElement(Ns + "Enabled", "true"),
                    new XElement(Ns + "ExecutionTimeLimit", "PT1H"),
                    new XElement(Ns + "RestartOnFailure",
                        new XElement(Ns + "Interval", "PT5M"),
                        new XElement(Ns + "Count", "3"))),
                new XElement(Ns + "Actions",
                    new XAttribute("Context", "System"),
                    new XElement(Ns + "Exec",
                        new XElement(Ns + "Command", executable),
                        new XElement(Ns + "Arguments", arguments)))));
        return doc.ToString();
    }

    public static string BuildShareTask(string taskName, string executable, string arguments, string description, bool hourly)
        => Build(taskName, executable, arguments, description, eventTrigger: false, hourly: hourly);

    public static string BuildSystemCommand(string taskName, string executable, string arguments, string description)
        => Build(taskName, executable, arguments, description, eventTrigger: false);

    public static string BuildExportTask(string taskName, string executable, string configPath)
    {
        PathGuard.RequireSafePath(configPath);
        var arguments = "export --config \"" + configPath + "\"";
        return Build(taskName, executable, arguments, "Exports IIS certificates into the Central Certificate Store after renewal.", eventTrigger: true);
    }

    private static string EventQuery()
    {
        return """
            <QueryList>
              <Query Id="0" Path="Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational">
                <Select Path="Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational">*[System[(EventID=1001)]]</Select>
              </Query>
            </QueryList>
            """;
    }
}
