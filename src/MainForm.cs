using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RedirectCraftPatcher
{
    internal sealed class MainForm : Form
    {
        private readonly TextBox folderBox = new TextBox();
        private readonly Button browseButton = new Button();
        private readonly Button analyzeButton = new Button();
        private readonly Button patchButton = new Button();
        private readonly Button restoreButton = new Button();
        private readonly Button aboutButton = new Button();
        private readonly Label statusBadge = new Label();
        private readonly Label operationBadge = new Label();
        private readonly RichTextBox detailsBox = new RichTextBox();
        private AnalysisResult analysis;

        private static readonly Color Green = Color.FromArgb(25, 135, 84);
        private static readonly Color Red = Color.FromArgb(220, 53, 69);
        private static readonly Color Blue = Color.FromArgb(13, 110, 253);
        private static readonly Color Gray = Color.FromArgb(108, 117, 125);

        public MainForm()
        {
            Text = "合成台重定向补丁工具";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(880, 640);
            MinimumSize = new Size(760, 560);
            Font = new Font("Microsoft YaHei UI", 9F);
            AutoScaleMode = AutoScaleMode.Dpi;
            BackColor = Color.FromArgb(245, 247, 250);

            Label title = new Label();
            title.Text = "合成台重定向补丁工具";
            title.Font = new Font("Microsoft YaHei UI", 18F, FontStyle.Bold);
            title.AutoSize = true;
            title.Location = new Point(22, 18);

            Label subtitle = new Label();
            subtitle.Text = "选择芙芙启动器文件夹，程序会自动定位主插件";
            subtitle.ForeColor = Color.DimGray;
            subtitle.AutoSize = true;
            subtitle.Location = new Point(25, 57);

            Label folderLabel = new Label();
            folderLabel.Text = "启动器文件夹";
            folderLabel.AutoSize = true;
            folderLabel.Location = new Point(25, 94);

            folderBox.Location = new Point(25, 118);
            folderBox.Size = new Size(700, 25);
            folderBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            browseButton.Text = "选择...";
            browseButton.Location = new Point(735, 115);
            browseButton.Size = new Size(105, 31);
            browseButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            browseButton.Click += BrowseButtonClick;

            statusBadge.TextAlign = ContentAlignment.MiddleCenter;
            statusBadge.Font = new Font("Segoe UI", 18F, FontStyle.Bold);
            statusBadge.ForeColor = Color.White;
            statusBadge.BackColor = Gray;
            statusBadge.Text = "NOT ANALYZED";
            statusBadge.Location = new Point(25, 160);
            statusBadge.Size = new Size(250, 54);

            operationBadge.TextAlign = ContentAlignment.MiddleCenter;
            operationBadge.Font = new Font("Microsoft YaHei UI", 11F, FontStyle.Bold);
            operationBadge.ForeColor = Color.White;
            operationBadge.BackColor = Gray;
            operationBadge.Text = "等待操作";
            operationBadge.Location = new Point(290, 160);
            operationBadge.Size = new Size(550, 54);
            operationBadge.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

            analyzeButton.Text = "Analyze 分析";
            analyzeButton.Location = new Point(25, 230);
            analyzeButton.Size = new Size(135, 38);
            analyzeButton.Click += async delegate { await AnalyzeAsync(); };

            patchButton.Text = "Patch 应用补丁";
            patchButton.Location = new Point(170, 230);
            patchButton.Size = new Size(145, 38);
            patchButton.Enabled = false;
            patchButton.Click += async delegate { await PatchAsync(); };

            restoreButton.Text = "Restore 还原";
            restoreButton.Location = new Point(325, 230);
            restoreButton.Size = new Size(135, 38);
            restoreButton.Click += async delegate { await RestoreAsync(); };

            aboutButton.Text = "说明与许可证";
            aboutButton.Location = new Point(470, 230);
            aboutButton.Size = new Size(140, 38);
            aboutButton.Click += AboutButtonClick;

            detailsBox.Location = new Point(25, 284);
            detailsBox.Size = new Size(815, 300);
            detailsBox.Anchor = AnchorStyles.Top | AnchorStyles.Bottom |
                AnchorStyles.Left | AnchorStyles.Right;
            detailsBox.ReadOnly = true;
            detailsBox.BackColor = Color.White;
            detailsBox.Font = new Font("Consolas", 9F);
            detailsBox.WordWrap = false;
            detailsBox.Text = "目标相对路径：\r\n" + PatchEngine.RelativeDllPath;

            Controls.AddRange(new Control[] { title, subtitle, folderLabel, folderBox,
                browseButton, statusBadge, operationBadge, analyzeButton, patchButton,
                restoreButton, aboutButton, detailsBox });

            string initial = SettingsStore.LoadLauncherFolder();
            if (!string.IsNullOrEmpty(initial)) folderBox.Text = initial;
        }

        protected override async void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (!string.IsNullOrWhiteSpace(folderBox.Text)) await AnalyzeAsync();
        }

        private void BrowseButtonClick(object sender, EventArgs e)
        {
            using (FolderBrowserDialog dialog = new FolderBrowserDialog())
            {
                dialog.Description = "选择芙芙启动器的最外层文件夹";
                dialog.ShowNewFolderButton = false;
                if (Directory.Exists(folderBox.Text)) dialog.SelectedPath = folderBox.Text;
                if (dialog.ShowDialog(this) == DialogResult.OK)
                {
                    folderBox.Text = dialog.SelectedPath;
                    SettingsStore.SaveLauncherFolder(dialog.SelectedPath);
                    BeginInvoke(new Action(async delegate { await AnalyzeAsync(); }));
                }
            }
        }

        private async Task AnalyzeAsync()
        {
            if (string.IsNullOrWhiteSpace(folderBox.Text))
            {
                SetAnalysisBadge(AnalysisState.Unpatchable);
                SetOperation("请选择芙芙启动器文件夹", Red);
                return;
            }

            SetBusy(true);
            SetOperation("正在分析，UPX 版本可能需要数秒……", Blue);
            try
            {
                string folder = folderBox.Text.Trim();
                analysis = await Task.Run(delegate { return PatchEngine.Analyze(folder); });
                SettingsStore.SaveLauncherFolder(folder);
                SetAnalysisBadge(analysis.State);
                SetOperation(analysis.Message,
                    analysis.State == AnalysisState.Unpatchable ? Red :
                    analysis.State == AnalysisState.Patched ? Blue : Green);
                patchButton.Enabled = analysis.CanPatch;
                detailsBox.Text = FormatAnalysis(analysis);
            }
            catch (Exception ex)
            {
                analysis = null;
                patchButton.Enabled = false;
                SetAnalysisBadge(AnalysisState.Unpatchable);
                SetOperation("分析失败", Red);
                detailsBox.Text = ex.Message;
            }
            finally { SetBusy(false); }
        }

        private async Task PatchAsync()
        {
            if (analysis == null || !analysis.CanPatch) return;
            DialogResult answer = MessageBox.Show(this,
                "请先完全退出游戏和芙芙启动器。\r\n\r\n" +
                "程序会保留官方原始 DLL 备份。补丁后的 DLL 数字签名将失效；" +
                "若原文件使用 UPX，补丁文件会保持解压状态。是否继续？",
                "确认应用补丁", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;

            SetBusy(true);
            SetOperation("正在创建备份并应用补丁……", Blue);
            try
            {
                PatchOutcome outcome = await Task.Run(delegate
                {
                    return PatchEngine.ApplyPatch(analysis);
                });
                SetOperation("PATCH SUCCEEDED · 补丁应用成功", Green);
                detailsBox.Text += "\r\n\r\nPATCH SUCCEEDED\r\nPatched SHA-256: " +
                    outcome.PatchedSha256 + "\r\nBackup: " + outcome.BackupPath +
                    "\r\nManifest: " + outcome.ManifestPath;
                analysis = await Task.Run(delegate { return PatchEngine.Analyze(folderBox.Text.Trim()); });
                SetAnalysisBadge(AnalysisState.Patched);
                patchButton.Enabled = false;
            }
            catch (Exception ex)
            {
                SetOperation("PATCH FAILED · 未修改或已自动恢复", Red);
                detailsBox.Text += "\r\n\r\nERROR: " + ex.Message;
            }
            finally { SetBusy(false); }
        }

        private async Task RestoreAsync()
        {
            if (string.IsNullOrWhiteSpace(folderBox.Text))
            {
                SetOperation("请先选择启动器文件夹", Red);
                return;
            }
            DialogResult answer = MessageBox.Show(this,
                "将根据 JSON 清单校验并还原官方原始 DLL。是否继续？",
                "确认还原", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (answer != DialogResult.Yes) return;

            SetBusy(true);
            SetOperation("正在校验并还原……", Blue);
            try
            {
                string folder = folderBox.Text.Trim();
                RestoreOutcome outcome = await Task.Run(delegate
                {
                    return PatchEngine.Restore(folder);
                });
                SetOperation("RESTORE SUCCEEDED · 已还原官方 DLL", Blue);
                detailsBox.Text = "RESTORE SUCCEEDED\r\nSHA-256: " +
                    outcome.RestoredSha256 + "\r\nBackup retained: " + outcome.BackupPath;
                analysis = await Task.Run(delegate { return PatchEngine.Analyze(folder); });
                SetAnalysisBadge(analysis.State);
                patchButton.Enabled = analysis.CanPatch;
            }
            catch (Exception ex)
            {
                SetOperation("RESTORE FAILED · 还原失败", Red);
                detailsBox.Text += "\r\n\r\nERROR: " + ex.Message;
            }
            finally { SetBusy(false); }
        }

        private void AboutButtonClick(object sender, EventArgs e)
        {
            string text = "Fufu RedirectCraft Patcher " + PatchEngine.ToolVersion +
                "\r\n\r\n内置 UPX 5.2.0，仅用于解包受支持的官方插件副本。" +
                "完整 UPX 许可证已嵌入本 EXE。\r\n\r\n" +
                "本工具采用安全拒绝策略：无法唯一证明目标控制流时不会写入 DLL。";
            MessageBox.Show(this, text, "说明与许可证",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private string FormatAnalysis(AnalysisResult value)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Launcher:  " + value.LauncherFolder);
            builder.AppendLine("DLL:       " + value.DllPath);
            builder.AppendLine("Version:   " + value.Version);
            builder.AppendLine("SHA-256:   " + value.OriginalSha256);
            builder.AppendLine("Signature: " + value.Signature);
            builder.AppendLine("UPX:       " + (value.WasUpxPacked ? "Yes (unpacked in memory/temp)" : "No"));
            builder.AppendLine("State:     " + value.State);
            builder.AppendLine("Detector:  " + value.Detector);
            if (value.PatchOffset >= 0)
            {
                builder.AppendLine("Offset:    0x" + value.PatchOffset.ToString("X"));
                builder.AppendLine("RVA:       0x" + value.PatchRva.ToString("X"));
                builder.AppendLine("Before:    " + PatchEngine.BytesToHex(value.OriginalBytes));
                builder.AppendLine("After:     " + PatchEngine.BytesToHex(value.PatchedBytes));
            }
            builder.AppendLine();
            builder.AppendLine(value.Message);
            return builder.ToString();
        }

        private void SetAnalysisBadge(AnalysisState state)
        {
            if (state == AnalysisState.Patchable)
            {
                statusBadge.Text = "PATCHABLE";
                statusBadge.BackColor = Green;
            }
            else if (state == AnalysisState.Patched)
            {
                statusBadge.Text = "PATCHED";
                statusBadge.BackColor = Blue;
            }
            else
            {
                statusBadge.Text = "UNPATCHABLE";
                statusBadge.BackColor = Red;
            }
        }

        private void SetOperation(string text, Color color)
        {
            operationBadge.Text = text;
            operationBadge.BackColor = color;
        }

        private void SetBusy(bool busy)
        {
            UseWaitCursor = busy;
            browseButton.Enabled = !busy;
            analyzeButton.Enabled = !busy;
            restoreButton.Enabled = !busy;
            aboutButton.Enabled = !busy;
            if (busy) patchButton.Enabled = false;
        }
    }
}
