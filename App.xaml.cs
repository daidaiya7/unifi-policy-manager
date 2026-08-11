using System.Windows;
using UniFiDnsManager.Services;

namespace UniFiDnsManager;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var selfTestArg = e.Args.FirstOrDefault(arg => arg.StartsWith("--self-test-output=", StringComparison.OrdinalIgnoreCase));
        if (e.Args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            var output = selfTestArg?.Split('=', 2)[1] ?? Path.Combine(Path.GetTempPath(), "unifi-dns-manager-self-test.json");
            var success = await SelfTest.RunAsync(output);
            Shutdown(success ? 0 : 1);
            return;
        }

        var demo = e.Args.Contains("--demo", StringComparer.OrdinalIgnoreCase);
        var window = new MainWindow(demo);
        MainWindow = window;
        window.Show();
    }
}
