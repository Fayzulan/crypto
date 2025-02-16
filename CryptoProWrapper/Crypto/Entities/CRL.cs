using Crypto.Interfaces;
using Crypto.Pivot;
using CryptoProWrapper;
using System.Runtime.InteropServices;

namespace Crypto.Entities
{
    internal class CRL : ICRL
    {
        public IntPtr handle { get; private set; }
        public bool released { get; private set; }
        private CryptoProWrapper.Crypto.CRL_CONTEXT? crlContext;

        public CRL()
        {
            InitEmpty();
        }

        public unsafe CRL(byte[] crlBytes)
        {
            fixed (byte* pCrlBytes = crlBytes)
            {
                nint newCRLContextPtr = Crypt32Helper.CertCreateCRLContext(PivotConstants.PKCS_7_OR_X509_ASN_ENCODING, (nint)(pCrlBytes), (uint)crlBytes.Length);

                if (newCRLContextPtr == 0)
                {
                    InitEmpty();
                }
                else
                {
                    InitFromPtr(newCRLContextPtr);
                }
            }
        }

        public CRL(IntPtr crlPtr)
        {
            InitFromPtr(crlPtr);
        }

        protected void InitEmpty()
        {
            handle = IntPtr.Zero;
            crlContext = null;
            released = false;
        }

        protected void InitFromPtr(nint crlPtr)
        {
            handle = crlPtr;

            if (handle != IntPtr.Zero)
            {
                crlContext = Marshal.PtrToStructure<CryptoProWrapper.Crypto.CRL_CONTEXT>(handle);
            }
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero && !released)
            {
                released = Crypt32Helper.CertFreeCRLContext(handle);
            }

            if (released) GC.SuppressFinalize(this);
        }

        //~CRL()
        //{
        //    Dispose();
        //}
    }
}
