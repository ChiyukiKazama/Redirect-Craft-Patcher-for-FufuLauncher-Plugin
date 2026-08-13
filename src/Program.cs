using System;
using System.Threading;
using System.Windows.Forms;

namespace RedirectCraftPatcher
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            bool created;
            using (Mutex mutex = new Mutex(true,
                "Local\\FufuRedirectCraftPatcher.SingleInstance", out created))
            {
                if (!created)
                {
                    MessageBox.Show("补丁工具已经在运行。", "合成台重定向补丁工具",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
        }
    }
}
