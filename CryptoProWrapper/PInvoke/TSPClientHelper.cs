using CryptoProWrapper.Enums;
using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    public class TSPClientHelper
    {
        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint HealthCheck();

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        //internal static extern int TestRequest([MarshalAs(UnmanagedType.LPStr)] string HashAlgorithmOID, [MarshalAs(UnmanagedType.LPStr)] string dest);
        internal static extern nint TestRequest([In] nint pTspRequestInfoPara);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        //internal static extern uint MakeRequest([In] nint pTspRequestInfoPara);
        internal static extern nint MakeRequest([In] uint toTimeStampLength, [In] nint toTimeStamp, [In] nint pCert, [Out] nint token, [Out] out uint tokenLength);




        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CRequestCreate();
        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CRequestCreate([Out] out nint CRequest);


        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern void CRequestDelete(nint Request);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CRequestPutTspAddress(nint Request, nint address);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CRequestPutDataHashAlg(nint Request, nint Alg);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CRequestAddData(nint Request, nint toTimeStamp);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CRequestPutClientCertificate(nint Request, nint pCert);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int CRequestGetHTTPStatus(nint Request);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CStampCreate(nint Request);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern void CStampDelete(nint Stamp);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CStampVerify(nint Stamp, nint pCert);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint CStampGetTokenLength(nint Stamp);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        //[return: MarshalAs(UnmanagedType.LPStr)]
        //internal static extern String CStampGetToken(nint Stamp, uint size);
        //internal static extern nint CStampGetToken(nint Stamp, uint size);
        internal static extern uint CStampGetToken(nint Stamp, uint size, ref IntPtr ptoken);
        //internal static extern uint CStampGetToken(nint Stamp, uint size, [In, Out] byte[] token);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int CStampGetFailInfo(nint Stamp);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern TspStatusCpde CStampGetStatus(nint Stamp);

        [DllImport(OSHelper.LinuxTSPClient, CharSet = CharSet.Unicode)]
        //[return: MarshalAs(UnmanagedType.LPStr)]
        internal static extern nint CStampGetStatusString(nint Stamp);
    }
}
