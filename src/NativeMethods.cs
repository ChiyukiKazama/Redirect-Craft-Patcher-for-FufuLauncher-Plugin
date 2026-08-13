using System;
using System.Runtime.InteropServices;

namespace RedirectCraftPatcher
{
    internal static class NativeMethods
    {
        private static readonly Guid WintrustActionGenericVerifyV2 =
            new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        private const uint WtdUiNone = 2;
        private const uint WtdRevokeNone = 0;
        private const uint WtdChoiceFile = 1;
        private const uint WtdStateActionIgnore = 0;
        private const uint WtdProvFlags = 0x00000010; // safer flag

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private sealed class WintrustFileInfo : IDisposable
        {
            public uint StructSize = (uint)Marshal.SizeOf(typeof(WintrustFileInfo));
            public IntPtr FilePath;
            public IntPtr FileHandle = IntPtr.Zero;
            public IntPtr KnownSubject = IntPtr.Zero;

            public WintrustFileInfo(string path)
            {
                FilePath = Marshal.StringToCoTaskMemUni(path);
            }

            public void Dispose()
            {
                if (FilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(FilePath);
                    FilePath = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private sealed class WintrustData : IDisposable
        {
            public uint StructSize = (uint)Marshal.SizeOf(typeof(WintrustData));
            public IntPtr PolicyCallbackData = IntPtr.Zero;
            public IntPtr SipClientData = IntPtr.Zero;
            public uint UIChoice = WtdUiNone;
            public uint RevocationChecks = WtdRevokeNone;
            public uint UnionChoice = WtdChoiceFile;
            public IntPtr FileInfoPointer;
            public uint StateAction = WtdStateActionIgnore;
            public IntPtr StateData = IntPtr.Zero;
            public IntPtr UrlReference = IntPtr.Zero;
            public uint ProvFlags = WtdProvFlags;
            public uint UIContext = 0;

            public WintrustData(WintrustFileInfo fileInfo)
            {
                FileInfoPointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WintrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, FileInfoPointer, false);
            }

            public void Dispose()
            {
                if (FileInfoPointer != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(FileInfoPointer, typeof(WintrustFileInfo));
                    Marshal.FreeCoTaskMem(FileInfoPointer);
                    FileInfoPointer = IntPtr.Zero;
                }
            }
        }

        [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true,
            CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
            WintrustData data);

        public static bool HasValidAuthenticodeSignature(string path)
        {
            using (WintrustFileInfo fileInfo = new WintrustFileInfo(path))
            using (WintrustData data = new WintrustData(fileInfo))
            {
                return WinVerifyTrust(IntPtr.Zero, WintrustActionGenericVerifyV2, data) == 0;
            }
        }
    }
}
