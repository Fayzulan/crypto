using System.Runtime.InteropServices;
using System.Text;

namespace CryptoProWrapper
{
    public class Kernel32Helper
    {
        [DllImport(OSHelper.Kernel32)]
        internal static extern uint FormatMessageC(
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            out string lpBuffer,
            uint nSize,
            IntPtr Arguments
        );



        [DllImport(OSHelper.Kernel32)]
        internal static extern uint GetLastError();

        // simplified for usability
        [DllImport(OSHelper.Kernel32)]
        internal static extern uint FormatMessage(
            uint dwFlags,
            nint lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            out StringBuilder msgOut,
            int nSize,
            nint Arguments
        );

        [DllImport(OSHelper.Kernel32)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport(OSHelper.Kernel32)]
        internal static extern uint GetCurrentProcessId();

        [DllImport(OSHelper.Kernel32)]
        internal static extern uint GetCurrentThreadId();
    }
}
