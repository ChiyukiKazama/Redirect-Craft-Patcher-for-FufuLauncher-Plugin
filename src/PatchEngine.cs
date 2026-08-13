using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace RedirectCraftPatcher
{
    internal static class PatchEngine
    {
        public const string ToolVersion = "1.0.0";
        public const string RelativeDllPath = @"FufuLauncher\Plugins\FuFuPlugin\FufuLauncher.UnlockerIsland.dll";
        public const string ExpectedFileName = "FufuLauncher.UnlockerIsland.dll";

        private const string CraftLog = "[Hotkey] Craft function triggered.";
        private const string AutoCookLog = "[Hotkey] Auto Cook function triggered.";
        private const string ConfigName = "RedirectCraft";
        private const string UpxResource = "Embedded.upx.exe";
        private const string UpxSha256 = "F4C0CC7ACA0F1FF0D0B750E966B44139F2FA1A2DB7281F48FC52194400712E1D";

        private static readonly HashSet<string> KnownOriginalHashes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "81CE64E376B05C565EB171500663AB655866D26DBE3A9F54013B6D501E0C113F",
                "18621B174A82F4E68B6D3C85FDC0D3F23DAA50DFAF80C5D5E8EE3561E19B9A1E"
            };

        private static readonly HashSet<string> KnownPatchedHashes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "A8E02FEBD45860304A15A4D27C12A12BA68C20ECA2B1CE25C1AE9CCCF8B87254",
                "7C17885227D3D891677DD9E0D7548EBF9671F935ADD30FA156680E34ADEE3F9B"
            };

        public static string ResolveDllPath(string selectedFolder)
        {
            if (string.IsNullOrWhiteSpace(selectedFolder)) return null;
            string root = Path.GetFullPath(selectedFolder.Trim());
            string preferred = Path.Combine(root, RelativeDllPath);
            if (File.Exists(preferred)) return preferred;

            // Also accept selecting the inner "FufuLauncher" directory itself.
            string inner = Path.Combine(root, @"Plugins\FuFuPlugin\" + ExpectedFileName);
            if (File.Exists(inner) &&
                string.Equals(new DirectoryInfo(root).Name, "FufuLauncher",
                    StringComparison.OrdinalIgnoreCase)) return inner;

            return preferred;
        }

        public static AnalysisResult Analyze(string launcherFolder)
        {
            AnalysisResult result = new AnalysisResult();
            result.LauncherFolder = launcherFolder;
            result.DllPath = ResolveDllPath(launcherFolder);
            result.State = AnalysisState.Unpatchable;
            result.Detector = "None";

            if (string.IsNullOrEmpty(result.DllPath) || !File.Exists(result.DllPath))
            {
                result.Message = "没有找到主插件：" + (result.DllPath ?? RelativeDllPath);
                return result;
            }

            if (!string.Equals(Path.GetFileName(result.DllPath), ExpectedFileName,
                StringComparison.OrdinalIgnoreCase))
            {
                result.Message = "主插件文件名不正确。";
                return result;
            }

            byte[] diskImage = File.ReadAllBytes(result.DllPath);
            PeImage diskPe = new PeImage(diskImage);
            result.OriginalSha256 = Sha256(diskImage);
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(result.DllPath);
            result.Version = string.IsNullOrEmpty(version.FileVersion) ? "(unknown)" : version.FileVersion;
            bool signatureValid = NativeMethods.HasValidAuthenticodeSignature(result.DllPath);
            result.Signature = signatureValid ? "Valid" : "Invalid / Not signed";
            result.WasUpxPacked = diskPe.HasSection("UPX0") && diskPe.HasSection("UPX1");

            PatchManifest matchedManifest;
            string matchedManifestPath;
            if (TryFindManifest(result.DllPath, result.OriginalSha256,
                out matchedManifest, out matchedManifestPath))
            {
                result.State = AnalysisState.Patched;
                result.Detector = "Verified local manifest";
                result.ManifestPath = matchedManifestPath;
                result.PatchOffset = matchedManifest.PatchOffset;
                result.PatchRva = matchedManifest.PatchRva;
                result.OriginalBytes = HexToBytes(matchedManifest.OriginalBytes);
                result.PatchedBytes = HexToBytes(matchedManifest.PatchedBytes);
                result.Message = "当前 DLL 已由本工具修改，并与本地校验清单一致。";
                return result;
            }

            if (KnownPatchedHashes.Contains(result.OriginalSha256))
            {
                result.State = AnalysisState.Patched;
                result.Detector = "Known patched hash";
                result.Message = "已识别为受支持版本的补丁 DLL。若要还原，需要同目录原始备份。";
                return result;
            }

            if (!signatureValid && !KnownOriginalHashes.Contains(result.OriginalSha256))
            {
                result.Message = "未知版本必须具有有效的官方数字签名；本文件未通过签名验证。";
                return result;
            }

            byte[] workingImage = diskImage;
            if (result.WasUpxPacked)
            {
                workingImage = UnpackWithEmbeddedUpx(result.DllPath);
                PeImage unpackedPe = new PeImage(workingImage);
                if (unpackedPe.HasSection("UPX0") || unpackedPe.HasSection("UPX1"))
                {
                    result.Message = "UPX 返回的文件仍处于压缩状态。";
                    return result;
                }
            }

            result.WorkingSha256 = Sha256(workingImage);
            StructuralCandidate candidate;
            string failure;
            if (!TryFindRedirectCraftGuard(workingImage, out candidate, out failure))
            {
                result.Message = failure;
                return result;
            }

            result.State = AnalysisState.Patchable;
            result.Detector = result.WasUpxPacked
                ? "Embedded UPX + semantic/control-flow detector"
                : "Semantic/control-flow detector";
            result.PatchOffset = candidate.Branch.Offset;
            result.PatchRva = candidate.Branch.Rva;
            result.OriginalBytes = candidate.Original;
            result.PatchedBytes = candidate.Patched;
            result.WorkingImage = workingImage;
            result.Message = "已唯一确认合成台场景条件；功能开关和其他功能的条件保持不变。";
            return result;
        }

        public static PatchOutcome ApplyPatch(AnalysisResult analysis)
        {
            if (analysis == null || !analysis.CanPatch)
                throw new InvalidOperationException("请先分析一个显示为 Patchable 的官方插件。");

            AssertUnlocked(analysis.DllPath);
            string currentHash = Sha256File(analysis.DllPath);
            if (!string.Equals(currentHash, analysis.OriginalSha256,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("DLL 在分析后发生了变化，请重新 Analyze。");

            byte[] patched = (byte[])analysis.WorkingImage.Clone();
            if (!TestBytes(patched, analysis.PatchOffset, analysis.OriginalBytes))
                throw new InvalidOperationException("补丁位置字节与分析结果不一致。");
            for (int index = 0; index < analysis.PatchedBytes.Length; index++)
                patched[analysis.PatchOffset + index] = analysis.PatchedBytes[index];

            VerifyOnlyPatchRangeChanged(analysis.WorkingImage, patched,
                analysis.PatchOffset, analysis.PatchedBytes.Length);
            new PeImage(patched);

            string directory = Path.GetDirectoryName(analysis.DllPath);
            string name = Path.GetFileName(analysis.DllPath);
            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string prefix = analysis.OriginalSha256.Substring(0, 12);
            string backup = Path.Combine(directory,
                name + "." + stamp + "." + prefix + ".fufu-backup");
            if (File.Exists(backup))
                backup = Path.Combine(directory, name + "." + stamp + "." + prefix + "." +
                    Guid.NewGuid().ToString("N") + ".fufu-backup");
            string manifestPath = backup + ".redirectcraft.json";
            string temp = Path.Combine(directory, "." + name + "." +
                Guid.NewGuid().ToString("N") + ".tmp");

            string expectedPatchedHash = Sha256(patched);
            try
            {
                File.WriteAllBytes(temp, patched);
                if (!string.Equals(Sha256File(temp), expectedPatchedHash,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("临时文件哈希验证失败。");
                new PeImage(File.ReadAllBytes(temp));

                File.Replace(temp, analysis.DllPath, backup, true);
                string installedHash = Sha256File(analysis.DllPath);
                string backupHash = Sha256File(backup);
                if (!string.Equals(backupHash, analysis.OriginalSha256,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("替换后原始备份哈希验证失败。");
                if (!string.Equals(installedHash, expectedPatchedHash,
                    StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(backup, analysis.DllPath, true);
                    throw new InvalidOperationException("补丁文件验证失败，已恢复原始 DLL。");
                }

                PatchManifest manifest = new PatchManifest();
                manifest.FormatVersion = 1;
                manifest.ToolVersion = ToolVersion;
                manifest.CreatedUtc = DateTime.UtcNow.ToString("o");
                manifest.TargetFileName = name;
                manifest.FileVersion = analysis.Version;
                manifest.OriginalWasUpxPacked = analysis.WasUpxPacked;
                manifest.Detector = analysis.Detector;
                manifest.OriginalSha256 = analysis.OriginalSha256;
                manifest.UnpackedSha256 = analysis.WorkingSha256;
                manifest.PatchedSha256 = installedHash;
                manifest.PatchOffset = analysis.PatchOffset;
                manifest.PatchRva = analysis.PatchRva;
                manifest.OriginalBytes = BytesToHex(analysis.OriginalBytes);
                manifest.PatchedBytes = BytesToHex(analysis.PatchedBytes);
                manifest.BackupFileName = Path.GetFileName(backup);
                WriteManifest(manifestPath, manifest);

                PatchOutcome outcome = new PatchOutcome();
                outcome.PatchedSha256 = installedHash;
                outcome.BackupPath = backup;
                outcome.ManifestPath = manifestPath;
                return outcome;
            }
            finally
            {
                TryDeleteFile(temp);
            }
        }

        public static RestoreOutcome Restore(string launcherFolder)
        {
            string target = ResolveDllPath(launcherFolder);
            if (string.IsNullOrEmpty(target) || !File.Exists(target))
                throw new FileNotFoundException("没有找到待还原的主插件。", target);

            string currentHash = Sha256File(target);
            PatchManifest manifest;
            string manifestPath;
            if (!TryFindManifest(target, currentHash, out manifest, out manifestPath))
                throw new InvalidOperationException("没有找到与当前 DLL 哈希匹配的备份清单。");

            string manifestDirectory = Path.GetDirectoryName(manifestPath);
            string backup = Path.GetFullPath(Path.Combine(manifestDirectory,
                manifest.BackupFileName));
            if (!string.Equals(Path.GetDirectoryName(backup), manifestDirectory,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("清单中的备份路径不安全。");
            if (!File.Exists(backup))
                throw new FileNotFoundException("备份文件不存在。", backup);
            if (!string.Equals(Sha256File(backup), manifest.OriginalSha256,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("备份哈希与清单不一致。");

            AssertUnlocked(target);
            string directory = Path.GetDirectoryName(target);
            string name = Path.GetFileName(target);
            string temp = Path.Combine(directory, "." + name + "." +
                Guid.NewGuid().ToString("N") + ".restore.tmp");
            string emergency = Path.Combine(directory, "." + name + "." +
                Guid.NewGuid().ToString("N") + ".restore-backup");
            try
            {
                File.Copy(backup, temp, false);
                File.Replace(temp, target, emergency, true);
                string restored = Sha256File(target);
                if (!string.Equals(restored, manifest.OriginalSha256,
                    StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(emergency, target, true);
                    throw new InvalidOperationException("还原验证失败，已放回补丁 DLL。");
                }
                RestoreOutcome outcome = new RestoreOutcome();
                outcome.RestoredSha256 = restored;
                outcome.BackupPath = backup;
                return outcome;
            }
            finally
            {
                TryDeleteFile(temp);
                TryDeleteFile(emergency);
            }
        }

        private sealed class StructuralCandidate
        {
            public BranchInfo Branch;
            public byte[] Original;
            public byte[] Patched;
        }

        private static bool TryFindRedirectCraftGuard(byte[] data,
            out StructuralCandidate found, out string failure)
        {
            found = null;
            failure = null;
            PeImage pe = new PeImage(data);
            List<long> configStrings = FindAscii(data, ConfigName + "\0");
            List<long> craftStrings = FindAscii(data, CraftLog + "\0");
            List<long> cookStrings = FindAscii(data, AutoCookLog + "\0");
            if (configStrings.Count != 1 || craftStrings.Count != 1 || cookStrings.Count != 1)
            {
                failure = string.Format(
                    "语义字符串缺失或不唯一（RedirectCraft={0}, Craft={1}, AutoCook={2}）。",
                    configStrings.Count, craftStrings.Count, cookStrings.Count);
                return false;
            }

            long configRva = pe.RawToRva(configStrings[0]);
            long craftRva = pe.RawToRva(craftStrings[0]);
            long cookRva = pe.RawToRva(cookStrings[0]);
            if (configRva < 0 || craftRva < 0 || cookRva < 0)
            {
                failure = "语义字符串不在有效 PE 节中。";
                return false;
            }

            List<CodeReference> configRefs = FindRipRelativeLeaReferences(data, pe, configRva);
            List<CodeReference> craftRefs = FindRipRelativeLeaReferences(data, pe, craftRva);
            List<CodeReference> cookRefs = FindRipRelativeLeaReferences(data, pe, cookRva);
            if (configRefs.Count != 1 || craftRefs.Count != 1 || cookRefs.Count < 1)
            {
                failure = string.Format(
                    "语义代码引用缺失或不唯一（RedirectCraft={0}, Craft={1}, AutoCook={2}）。",
                    configRefs.Count, craftRefs.Count, cookRefs.Count);
                return false;
            }

            int redirectCraftFieldOffset;
            if (!TryResolveConfigFieldOffset(data, pe, configRefs[0],
                out redirectCraftFieldOffset))
            {
                failure = "无法从 RedirectCraft 配置解析代码唯一推导其配置字段偏移。";
                return false;
            }

            List<StructuralCandidate> candidates = new List<StructuralCandidate>();
            foreach (CodeReference craftRef in craftRefs)
            {
                BranchInfo scene = GetJe(data, pe, craftRef.Offset - 6);
                if (scene == null) scene = GetJe(data, pe, craftRef.Offset - 2);
                if (scene == null || scene.Offset + scene.Length != craftRef.Offset) continue;
                if (!TestByteConditionEndingAt(data, scene.Offset)) continue;
                if (scene.TargetRva <= craftRef.Rva || scene.TargetRva - craftRef.Rva > 0x400 ||
                    !pe.IsExecutableRva(scene.TargetRva)) continue;

                List<BranchInfo> guards = new List<BranchInfo>();
                long searchStart = Math.Max(0, scene.Offset - 96);
                for (long offset = searchStart; offset < scene.Offset; offset++)
                {
                    BranchInfo guard = GetJe(data, pe, offset);
                    if (guard == null || guard.TargetRva != scene.TargetRva) continue;
                    int fieldOffset;
                    if (!TryGetCmpByteZeroFieldOffsetEndingAt(data, guard.Offset,
                        out fieldOffset)) continue;
                    if (fieldOffset != redirectCraftFieldOffset) continue;
                    guards.Add(guard);
                }
                if (guards.Count != 1 || guards[0].Offset >= scene.Offset) continue;

                RuntimeFunction function = FindRuntimeFunction(data, pe, scene.Rva);
                if (function == null || !Inside(function, craftRef.Rva) ||
                    !Inside(function, scene.TargetRva) || !Inside(function, guards[0].Rva)) continue;

                CodeReference nextCook = null;
                foreach (CodeReference reference in cookRefs)
                {
                    if (reference.Rva > craftRef.Rva &&
                        (nextCook == null || reference.Rva < nextCook.Rva)) nextCook = reference;
                }
                if (nextCook == null || !Inside(function, nextCook.Rva) ||
                    scene.TargetRva >= nextCook.Rva) continue;

                byte[] original = new byte[scene.Length];
                Buffer.BlockCopy(data, (int)scene.Offset, original, 0, scene.Length);
                byte[] patched = new byte[scene.Length];
                for (int index = 0; index < patched.Length; index++) patched[index] = 0x90;
                StructuralCandidate candidate = new StructuralCandidate();
                candidate.Branch = scene;
                candidate.Original = original;
                candidate.Patched = patched;
                candidates.Add(candidate);
            }

            if (candidates.Count != 1)
            {
                failure = "控制流验证得到 " + candidates.Count +
                    " 个候选位置；为避免误改，此版本被标记为 Unpatchable。";
                return false;
            }
            found = candidates[0];
            return true;
        }

        private static List<long> FindAscii(byte[] data, string text)
        {
            byte[] needle = Encoding.ASCII.GetBytes(text);
            List<long> hits = new List<long>();
            for (int offset = 0; offset <= data.Length - needle.Length; offset++)
            {
                if (data[offset] != needle[0]) continue;
                bool equal = true;
                for (int index = 1; index < needle.Length; index++)
                {
                    if (data[offset + index] != needle[index])
                    {
                        equal = false;
                        break;
                    }
                }
                if (equal) hits.Add(offset);
            }
            return hits;
        }

        private static List<CodeReference> FindRipRelativeLeaReferences(byte[] data,
            PeImage pe, long targetRva)
        {
            List<CodeReference> refs = new List<CodeReference>();
            foreach (PeSection section in pe.Sections)
            {
                if (!section.Executable) continue;
                long end = section.RawOffset + section.RawSize;
                for (long offset = section.RawOffset; offset <= end - 7; offset++)
                {
                    byte rex = data[offset];
                    if (rex < 0x48 || rex > 0x4F || data[offset + 1] != 0x8D) continue;
                    byte modRm = data[offset + 2];
                    if ((modRm & 0xC7) != 0x05) continue;
                    long instructionRva = pe.RawToRva(offset);
                    if (instructionRva < 0) continue;
                    int displacement = BitConverter.ToInt32(data, (int)offset + 3);
                    if (instructionRva + 7 + displacement == targetRva)
                    {
                        CodeReference reference = new CodeReference();
                        reference.Offset = offset;
                        reference.Rva = instructionRva;
                        refs.Add(reference);
                    }
                }
            }
            return refs;
        }

        private static BranchInfo GetJe(byte[] data, PeImage pe, long offset)
        {
            if (offset < 0 || offset >= data.LongLength) return null;
            int length;
            int displacement;
            if (offset + 6 <= data.LongLength && data[offset] == 0x0F && data[offset + 1] == 0x84)
            {
                length = 6;
                displacement = BitConverter.ToInt32(data, (int)offset + 2);
            }
            else if (offset + 2 <= data.LongLength && data[offset] == 0x74)
            {
                length = 2;
                displacement = unchecked((sbyte)data[offset + 1]);
            }
            else return null;

            long rva = pe.RawToRva(offset);
            if (rva < 0) return null;
            BranchInfo branch = new BranchInfo();
            branch.Offset = offset;
            branch.Rva = rva;
            branch.Length = length;
            branch.TargetRva = rva + length + displacement;
            return branch;
        }

        private static bool TestByteConditionEndingAt(byte[] data, long endOffset)
        {
            if (endOffset >= 2 && data[endOffset - 2] == 0x84)
            {
                byte modRm = data[endOffset - 1];
                if ((modRm & 0xC0) == 0xC0 && ((modRm >> 3) & 7) == (modRm & 7))
                    return true;
            }
            if (endOffset >= 3 && data[endOffset - 3] == 0x80 &&
                (data[endOffset - 2] & 0xF8) == 0xF8 && data[endOffset - 1] == 0)
                return true;
            return false;
        }

        private static bool TestCmpByteZeroEndingAt(byte[] data, long endOffset)
        {
            int ignored;
            return TryGetCmpByteZeroFieldOffsetEndingAt(data, endOffset, out ignored);
        }

        private static bool TryGetCmpByteZeroFieldOffsetEndingAt(byte[] data,
            long endOffset, out int fieldOffset)
        {
            fieldOffset = -1;
            long start = Math.Max(0, endOffset - 10);
            for (long offset = start; offset <= endOffset - 3; offset++)
            {
                if (data[offset] != 0x80) continue;
                int length = GetGroup80Length(data, offset);
                if (length <= 0 || offset + length != endOffset) continue;
                byte modRm = data[offset + 1];
                if ((modRm & 0x38) != 0x38 || data[endOffset - 1] != 0) continue;
                int mod = (modRm >> 6) & 3;
                int rm = modRm & 7;
                if (mod == 3 || rm == 4 || (mod == 0 && rm == 5)) continue;
                if (mod == 0) fieldOffset = 0;
                else if (mod == 1) fieldOffset = unchecked((sbyte)data[offset + 2]);
                else fieldOffset = BitConverter.ToInt32(data, (int)offset + 2);
                if (fieldOffset < 0) continue;
                return true;
            }
            return false;
        }

        private static bool TryResolveConfigFieldOffset(byte[] data, PeImage pe,
            CodeReference configReference, out int fieldOffset)
        {
            fieldOffset = -1;
            long flagRva = -1;
            long searchEnd = Math.Min(data.LongLength - 7, configReference.Offset + 40);
            for (long offset = configReference.Offset + 7; offset <= searchEnd; offset++)
            {
                if (data[offset] != 0x0F || data[offset + 1] != 0x95 ||
                    (data[offset + 2] & 0xC7) != 0x05) continue;
                long instructionRva = pe.RawToRva(offset);
                if (instructionRva < 0) return false;
                flagRva = instructionRva + 7 +
                    BitConverter.ToInt32(data, (int)offset + 3);
                break;
            }
            if (flagRva < 0) return false;

            PeSection text = pe.FindSection(".text");
            PeSection dataSection = pe.FindSection(".data");
            if (text == null || dataSection == null || flagRva < dataSection.Rva ||
                flagRva >= dataSection.Rva + Math.Max(dataSection.VirtualSize,
                    dataSection.RawSize)) return false;

            List<int> candidates = new List<int>();
            long end = text.RawOffset + text.RawSize;
            for (long offset = text.RawOffset; offset <= end - 8; offset++)
            {
                if (data[offset] != 0x48 || data[offset + 1] != 0x8D ||
                    data[offset + 2] != 0x05 || data[offset + 7] != 0xC3) continue;
                long instructionRva = pe.RawToRva(offset);
                if (instructionRva < 0) continue;
                long baseRva = instructionRva + 7 +
                    BitConverter.ToInt32(data, (int)offset + 3);
                long difference = flagRva - baseRva;
                if (baseRva >= dataSection.Rva && difference >= 0 && difference <= 0x400)
                    candidates.Add((int)difference);
            }
            if (candidates.Count != 1) return false;
            fieldOffset = candidates[0];
            return true;
        }

        private static int GetGroup80Length(byte[] data, long opcodeOffset)
        {
            if (opcodeOffset < 0 || opcodeOffset + 3 > data.LongLength || data[opcodeOffset] != 0x80)
                return 0;
            byte modRm = data[opcodeOffset + 1];
            int mod = (modRm >> 6) & 3;
            int rm = modRm & 7;
            long position = opcodeOffset + 2;
            if (mod != 3 && rm == 4)
            {
                if (position >= data.LongLength) return 0;
                byte sib = data[position++];
                if (mod == 0 && (sib & 7) == 5) position += 4;
            }
            if (mod == 0 && rm == 5) position += 4;
            else if (mod == 1) position++;
            else if (mod == 2) position += 4;
            position++;
            if (position > data.LongLength) return 0;
            return (int)(position - opcodeOffset);
        }

        private static RuntimeFunction FindRuntimeFunction(byte[] data, PeImage pe, long rva)
        {
            PeSection pdata = pe.FindSection(".pdata");
            if (pdata == null) return null;
            long end = pdata.RawOffset + pdata.RawSize;
            for (long offset = pdata.RawOffset; offset + 12 <= end; offset += 12)
            {
                long beginRva = BitConverter.ToUInt32(data, (int)offset);
                long endRva = BitConverter.ToUInt32(data, (int)offset + 4);
                if (beginRva == 0 && endRva == 0) continue;
                if (rva >= beginRva && rva < endRva)
                {
                    RuntimeFunction function = new RuntimeFunction();
                    function.BeginRva = beginRva;
                    function.EndRva = endRva;
                    return function;
                }
            }
            return null;
        }

        private static bool Inside(RuntimeFunction function, long rva)
        {
            return rva >= function.BeginRva && rva < function.EndRva;
        }

        private static byte[] UnpackWithEmbeddedUpx(string sourcePath)
        {
            string tempRoot = Path.Combine(Path.GetTempPath(),
                "FufuRedirectCraftPatcher-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempRoot);
            string upxPath = Path.Combine(tempRoot, "upx.exe");
            string outputPath = Path.Combine(tempRoot, "unpacked.dll");
            try
            {
                ExtractResource(UpxResource, upxPath);
                if (!string.Equals(Sha256File(upxPath), UpxSha256,
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("内置 UPX 的 SHA256 校验失败。");

                ProcessStartInfo info = new ProcessStartInfo();
                info.FileName = upxPath;
                info.Arguments = "-d -q -o \"" + outputPath + "\" \"" + sourcePath + "\"";
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.WindowStyle = ProcessWindowStyle.Hidden;
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                using (Process process = Process.Start(info))
                {
                    string stdout = process.StandardOutput.ReadToEnd();
                    string stderr = process.StandardError.ReadToEnd();
                    if (!process.WaitForExit(30000))
                    {
                        try { process.Kill(); } catch { }
                        throw new InvalidOperationException("UPX 解包超时。");
                    }
                    if (process.ExitCode != 0 || !File.Exists(outputPath))
                        throw new InvalidOperationException("UPX 无法解包此版本：" +
                            (stderr + " " + stdout).Trim());
                }
                return File.ReadAllBytes(outputPath);
            }
            finally
            {
                TryDeleteDirectory(tempRoot);
            }
        }

        private static void ExtractResource(string name, string path)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream source = assembly.GetManifestResourceStream(name))
            {
                if (source == null) throw new InvalidOperationException("缺少内置资源：" + name);
                using (FileStream target = new FileStream(path, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None)) source.CopyTo(target);
            }
        }

        public static string ReadEmbeddedText(string name)
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (stream == null) return "Embedded resource not found: " + name;
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
                    return reader.ReadToEnd();
            }
        }

        private static bool TryFindManifest(string targetPath, string currentHash,
            out PatchManifest manifest, out string manifestPath)
        {
            manifest = null;
            manifestPath = null;
            string directory = Path.GetDirectoryName(targetPath);
            string pattern = Path.GetFileName(targetPath) + ".*.redirectcraft.json";
            string[] files;
            try { files = Directory.GetFiles(directory, pattern); }
            catch { return false; }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            Array.Reverse(files);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            foreach (string file in files)
            {
                try
                {
                    PatchManifest candidate = serializer.Deserialize<PatchManifest>(
                        File.ReadAllText(file, Encoding.UTF8));
                    if (candidate != null &&
                        string.Equals(candidate.TargetFileName, Path.GetFileName(targetPath),
                            StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(candidate.PatchedSha256, currentHash,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        manifest = candidate;
                        manifestPath = file;
                        return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private static void WriteManifest(string path, PatchManifest manifest)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            string json = serializer.Serialize(manifest);
            File.WriteAllText(path, json, new UTF8Encoding(false));
        }

        private static void AssertUnlocked(string path)
        {
            try
            {
                using (FileStream stream = new FileStream(path, FileMode.Open,
                    FileAccess.ReadWrite, FileShare.None)) { }
            }
            catch (UnauthorizedAccessException)
            {
                throw new InvalidOperationException("没有写入权限，请右键以管理员身份运行本工具。");
            }
            catch (IOException)
            {
                throw new InvalidOperationException("DLL 正在被占用，请完全退出游戏和启动器。", null);
            }
        }

        private static void VerifyOnlyPatchRangeChanged(byte[] before, byte[] after,
            long patchOffset, int patchLength)
        {
            if (before.Length != after.Length)
                throw new InvalidOperationException("内部验证失败：文件长度发生变化。");
            int differences = 0;
            for (long index = 0; index < before.LongLength; index++)
            {
                if (before[index] == after[index]) continue;
                differences++;
                if (index < patchOffset || index >= patchOffset + patchLength)
                    throw new InvalidOperationException("内部验证失败：补丁范围外字节发生变化。");
            }
            if (differences != patchLength)
                throw new InvalidOperationException("内部验证失败：实际修改字节数不正确。");
        }

        private static bool TestBytes(byte[] data, long offset, byte[] expected)
        {
            if (data == null || expected == null || offset < 0 ||
                offset + expected.Length > data.LongLength) return false;
            for (int index = 0; index < expected.Length; index++)
                if (data[offset + index] != expected[index]) return false;
            return true;
        }

        public static string Sha256File(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 sha = SHA256.Create()) return BytesToHex(sha.ComputeHash(stream));
        }

        private static string Sha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create()) return BytesToHex(sha.ComputeHash(data));
        }

        public static string BytesToHex(byte[] bytes)
        {
            if (bytes == null) return string.Empty;
            StringBuilder builder = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) builder.Append(value.ToString("X2"));
            return builder.ToString();
        }

        private static byte[] HexToBytes(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length % 2 != 0) return new byte[0];
            byte[] bytes = new byte[value.Length / 2];
            for (int index = 0; index < bytes.Length; index++)
                bytes[index] = Convert.ToByte(value.Substring(index * 2, 2), 16);
            return bytes;
        }

        private static void TryDeleteFile(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        private static void TryDeleteDirectory(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (!Directory.Exists(path)) return;
                string full = Path.GetFullPath(path);
                string temp = Path.GetFullPath(Path.GetTempPath());
                if (full.StartsWith(temp, StringComparison.OrdinalIgnoreCase) &&
                    new DirectoryInfo(full).Name.StartsWith("FufuRedirectCraftPatcher-",
                        StringComparison.Ordinal)) Directory.Delete(full, true);
            }
            catch { }
        }
    }
}
