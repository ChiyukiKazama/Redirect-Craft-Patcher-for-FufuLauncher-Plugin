using System;
using System.IO;

namespace RedirectCraftPatcher
{
    internal static class IntegrationHarness
    {
        private static int Main(string[] args)
        {
            if (args.Length != 1 || !File.Exists(args[0]))
            {
                Console.Error.WriteLine("Usage: IntegrationHarness <official-dll>");
                return 2;
            }

            string root = Path.Combine(Path.GetTempPath(),
                "FufuPatcherIntegration-" + Guid.NewGuid().ToString("N"));
            string pluginDirectory = Path.Combine(root,
                @"FufuLauncher\Plugins\FuFuPlugin");
            Directory.CreateDirectory(pluginDirectory);
            string target = Path.Combine(pluginDirectory, PatchEngine.ExpectedFileName);
            File.Copy(args[0], target, false);
            string originalHash = PatchEngine.Sha256File(target);

            try
            {
                AnalysisResult first = PatchEngine.Analyze(root);
                Console.WriteLine("InitialState={0}", first.State);
                Console.WriteLine("InitialVersion={0}", first.Version);
                Console.WriteLine("WasUpxPacked={0}", first.WasUpxPacked);
                Console.WriteLine("PatchOffset=0x{0:X}", first.PatchOffset);
                if (first.State != AnalysisState.Patchable || !first.WasUpxPacked)
                    throw new InvalidOperationException("Expected a patchable UPX image.");

                PatchOutcome patched = PatchEngine.ApplyPatch(first);
                Console.WriteLine("PatchedHash={0}", patched.PatchedSha256);
                if (!File.Exists(patched.BackupPath) || !File.Exists(patched.ManifestPath))
                    throw new InvalidOperationException("Backup artifacts are missing.");

                AnalysisResult second = PatchEngine.Analyze(root);
                Console.WriteLine("SecondState={0}", second.State);
                if (second.State != AnalysisState.Patched)
                    throw new InvalidOperationException("Patched state was not recognized.");

                RestoreOutcome restored = PatchEngine.Restore(root);
                Console.WriteLine("RestoredHash={0}", restored.RestoredSha256);
                if (!string.Equals(restored.RestoredSha256, originalHash,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Restore hash mismatch.");
                Console.WriteLine("RestoredSignatureValid={0}",
                    NativeMethods.HasValidAuthenticodeSignature(target));

                AnalysisResult third = PatchEngine.Analyze(root);
                Console.WriteLine("FinalState={0}", third.State);
                if (third.State != AnalysisState.Patchable)
                    throw new InvalidOperationException("Restored original is not patchable.");
                Console.WriteLine("PASS");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
                return 1;
            }
            finally
            {
                try
                {
                    string full = Path.GetFullPath(root);
                    string temp = Path.GetFullPath(Path.GetTempPath());
                    if (full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                        new DirectoryInfo(full).Name.StartsWith(
                            "FufuPatcherIntegration-", StringComparison.Ordinal))
                        Directory.Delete(full, true);
                }
                catch { }
            }
        }
    }
}
