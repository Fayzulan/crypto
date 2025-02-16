using CryptoProWrapper;
using System.Runtime.InteropServices;

namespace CryptoAPI
{
    public class StoreChainBuilder : IChainBuilder
    {
        public IntPtr Build(IntPtr certificate, ChainValidationParameters chainValidationParameters)
        {
            if (certificate == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }
            else
            {
                CryptStructure.CertChainParameters chainParameters = new CryptStructure.CertChainParameters();
                chainParameters.cbSize = Marshal.SizeOf(typeof(CryptStructure.CertChainParameters));
                //chainParameters.RevocationChecks = CertRevocationCheckFlags.ChainExcludeRoot;

                IntPtr chainContextPtr = IntPtr.Zero;

                long t = chainValidationParameters.ValidationTime.ToFileTime();

                CryptStructure.FILETIME filetimeStruct = new CryptStructure.FILETIME();
                filetimeStruct.Low = (uint)(t);
                filetimeStruct.High = (uint)(t >> 32);

                nint time = Marshal.AllocHGlobal(Marshal.SizeOf(filetimeStruct));

                try
                {
                    Marshal.StructureToPtr<CryptStructure.FILETIME>(filetimeStruct, time, true);

                    bool success = Crypt32Helper.CertGetCertificateChain(
                        IntPtr.Zero,
                        certificate,
                        time,
                        IntPtr.Zero,
                        chainParameters,
                        0,
                        IntPtr.Zero,
                        out chainContextPtr
                    );
                }
                finally
                {
                    if (time != 0) Marshal.FreeHGlobal(time);
                }

                return chainContextPtr;
            }
        }
    }
}
