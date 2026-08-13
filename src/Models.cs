using System;
using System.Collections.Generic;

namespace RedirectCraftPatcher
{
    internal enum AnalysisState
    {
        Unpatchable,
        Patchable,
        Patched
    }

    internal sealed class AnalysisResult
    {
        public string LauncherFolder;
        public string DllPath;
        public string Version;
        public string OriginalSha256;
        public string WorkingSha256;
        public string Signature;
        public bool WasUpxPacked;
        public AnalysisState State;
        public string Detector;
        public long PatchOffset = -1;
        public long PatchRva = -1;
        public byte[] OriginalBytes;
        public byte[] PatchedBytes;
        public byte[] WorkingImage;
        public string Message;
        public string ManifestPath;

        public bool CanPatch
        {
            get { return State == AnalysisState.Patchable && WorkingImage != null; }
        }
    }

    internal sealed class PatchOutcome
    {
        public string PatchedSha256;
        public string BackupPath;
        public string ManifestPath;
    }

    internal sealed class RestoreOutcome
    {
        public string RestoredSha256;
        public string BackupPath;
    }

    internal sealed class PatchManifest
    {
        public int FormatVersion { get; set; }
        public string ToolVersion { get; set; }
        public string CreatedUtc { get; set; }
        public string TargetFileName { get; set; }
        public string FileVersion { get; set; }
        public bool OriginalWasUpxPacked { get; set; }
        public string Detector { get; set; }
        public string OriginalSha256 { get; set; }
        public string UnpackedSha256 { get; set; }
        public string PatchedSha256 { get; set; }
        public long PatchOffset { get; set; }
        public long PatchRva { get; set; }
        public string OriginalBytes { get; set; }
        public string PatchedBytes { get; set; }
        public string BackupFileName { get; set; }
    }

    internal sealed class PeSection
    {
        public string Name;
        public long Rva;
        public long VirtualSize;
        public long RawOffset;
        public long RawSize;
        public bool Executable;
    }

    internal sealed class PeImage
    {
        public readonly byte[] Data;
        public readonly List<PeSection> Sections = new List<PeSection>();

        public PeImage(byte[] data)
        {
            Data = data;
            Parse();
        }

        private void Parse()
        {
            RequireRange(0, 0x40, "DOS header");
            if (Data[0] != 0x4D || Data[1] != 0x5A)
                throw new InvalidOperationException("文件不是有效的 PE 镜像（缺少 MZ）。");

            int peOffset = BitConverter.ToInt32(Data, 0x3C);
            RequireRange(peOffset, 24, "PE header");
            if (Data[peOffset] != 0x50 || Data[peOffset + 1] != 0x45 ||
                Data[peOffset + 2] != 0 || Data[peOffset + 3] != 0)
                throw new InvalidOperationException("PE 签名无效。");

            ushort machine = BitConverter.ToUInt16(Data, peOffset + 4);
            ushort sectionCount = BitConverter.ToUInt16(Data, peOffset + 6);
            ushort optionalSize = BitConverter.ToUInt16(Data, peOffset + 20);
            ushort characteristics = BitConverter.ToUInt16(Data, peOffset + 22);
            int optionalOffset = peOffset + 24;
            RequireRange(optionalOffset, optionalSize, "optional header");

            if (machine != 0x8664)
                throw new InvalidOperationException("仅支持 AMD64 插件 DLL。");
            if (BitConverter.ToUInt16(Data, optionalOffset) != 0x20B)
                throw new InvalidOperationException("仅支持 PE32+ 镜像。");
            if ((characteristics & 0x2000) == 0)
                throw new InvalidOperationException("目标 PE 没有 DLL 标记。");
            if (sectionCount < 1 || sectionCount > 96)
                throw new InvalidOperationException("PE 节数量异常。");

            int sectionTable = optionalOffset + optionalSize;
            RequireRange(sectionTable, sectionCount * 40, "section table");
            for (int index = 0; index < sectionCount; index++)
            {
                int offset = sectionTable + index * 40;
                string name = System.Text.Encoding.ASCII.GetString(Data, offset, 8).TrimEnd('\0');
                PeSection section = new PeSection();
                section.Name = name;
                section.VirtualSize = BitConverter.ToUInt32(Data, offset + 8);
                section.Rva = BitConverter.ToUInt32(Data, offset + 12);
                section.RawSize = BitConverter.ToUInt32(Data, offset + 16);
                section.RawOffset = BitConverter.ToUInt32(Data, offset + 20);
                uint flags = BitConverter.ToUInt32(Data, offset + 36);
                section.Executable = (flags & 0x20000000U) != 0;
                RequireRange(section.RawOffset, section.RawSize, "section " + name);
                Sections.Add(section);
            }
        }

        private void RequireRange(long offset, long length, string description)
        {
            if (offset < 0 || length < 0 || offset + length > Data.LongLength)
                throw new InvalidOperationException("PE 范围无效：" + description + "。");
        }

        public long RawToRva(long rawOffset)
        {
            foreach (PeSection section in Sections)
            {
                if (rawOffset >= section.RawOffset && rawOffset < section.RawOffset + section.RawSize)
                    return section.Rva + rawOffset - section.RawOffset;
            }
            return -1;
        }

        public bool IsExecutableRva(long rva)
        {
            foreach (PeSection section in Sections)
            {
                long mapped = Math.Max(section.VirtualSize, section.RawSize);
                if (section.Executable && rva >= section.Rva && rva < section.Rva + mapped)
                    return true;
            }
            return false;
        }

        public PeSection FindSection(string name)
        {
            foreach (PeSection section in Sections)
                if (string.Equals(section.Name, name, StringComparison.Ordinal)) return section;
            return null;
        }

        public bool HasSection(string name)
        {
            return FindSection(name) != null;
        }
    }

    internal sealed class BranchInfo
    {
        public long Offset;
        public long Rva;
        public int Length;
        public long TargetRva;
    }

    internal sealed class CodeReference
    {
        public long Offset;
        public long Rva;
    }

    internal sealed class RuntimeFunction
    {
        public long BeginRva;
        public long EndRva;
    }
}
