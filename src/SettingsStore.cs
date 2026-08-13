using System;
using System.IO;
using System.Text;

namespace RedirectCraftPatcher
{
    internal static class SettingsStore
    {
        private static string SettingsPath
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                    "FufuRedirectCraftPatcher", "launcher-folder.txt");
            }
        }

        public static string LoadLauncherFolder()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return null;
                string value = File.ReadAllText(SettingsPath, Encoding.UTF8).Trim();
                return Directory.Exists(value) ? value : null;
            }
            catch { return null; }
        }

        public static void SaveLauncherFolder(string value)
        {
            try
            {
                string directory = Path.GetDirectoryName(SettingsPath);
                Directory.CreateDirectory(directory);
                File.WriteAllText(SettingsPath, value ?? string.Empty,
                    new UTF8Encoding(false));
            }
            catch { }
        }
    }
}
