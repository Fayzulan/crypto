using Crypto.Helpers;
using Crypto.Interfaces;
using Crypto.Pivot;
using CryptoProWrapper;
using CryptStructure;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Crypto.Entities
{
    public unsafe class CCertificate : ICCertificate
    {
        public CryptoProWrapper.Crypto.CERT_CONTEXT context { get; private set; }
        public IntPtr handle { get; private set; }
        public bool released { get; private set; }
        public string serialNumber { get; private set; }
        public byte[] serialNumberBytes { get; private set; }
        public string issuer { get; private set; }
        public string subject { get; private set; }
        public byte[] issuerBytes { get; private set; }
        public byte[] subjectBytes { get; private set; }
        public byte[] authorityUniqueIdentifier { get; private set; }
        public byte[] subjectUniqueIdentifier { get; private set; }
        public /*PointerStructures.FILETIME*/System.Runtime.InteropServices.ComTypes.FILETIME notBeforeFiletime { get; private set; }
        public DateTime notBefore { get; private set; }
        public /*PointerStructures.FILETIME*/System.Runtime.InteropServices.ComTypes.FILETIME notAfterFiletime { get; private set; }
        public DateTime notAfter { get; private set; }
        public DateTime? notBeforeKey { get; private set; }
        public DateTime? notAfterKey { get; private set; }
        public bool isPrivateKeyExpired
        {
            get
            {
                return notAfterKey?.Date.CompareTo(DateTime.Now.Date) < 0 && notBeforeKey?.Date != null && notBeforeKey?.Date != DateTime.MinValue;
            }
        }
        public string KeyAlgorithmOid { get; private set; }
        public string HashAlgorithmOid { get; private set; }
        public string issuerUniqueId { get; private set; }
        public string issuerCertURL { get; private set; }
        public string crlURL { get; private set; }
        public bool isSelfSigned
        {
            get
            {
                return PivotFunctionsHelper.CompareByteArrays(issuerBytes, subjectBytes);
            }
        }

        private CryptoProWrapper.Crypto.CERT_CONTEXT? certContext;

        public CCertificate()
        {
            InitEmpty();
        }

        public bool HasPersistedPrivateKey => CertHasProperty(CryptStructure.Constants.CERT_KEY_PROV_INFO_PROP_ID);
        public bool HasEphemeralPrivateKey => CertHasProperty(CryptStructure.Constants.CERT_KEY_CONTEXT_PROP_ID);
        public bool ContainsPrivateKey => HasPersistedPrivateKey || HasEphemeralPrivateKey;



        private bool CertHasProperty(uint propertyId)
        {
            bool found = false;
            try
            {
                IntPtr certhandle = handle;
                uint pcbData = 0;
                if (Crypt32Helper.CertGetCertificateContextProperty(certhandle, propertyId, IntPtr.Zero, ref pcbData))
                {
                    found = true;
                    IntPtr memoryChunk = Marshal.AllocHGlobal((int)pcbData);
                    try
                    {

                        if (Crypt32Helper.CertGetCertificateContextProperty(certhandle, 2, memoryChunk, ref pcbData))
                        {
                            CRYPT_KEY_PROV_INFO? context = (CRYPT_KEY_PROV_INFO?)Marshal.PtrToStructure(memoryChunk, typeof(CRYPT_KEY_PROV_INFO));
                        }
                        else
                        {
                            throw new Exception("сбой :( !");
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(memoryChunk);
                    }
                }
                else
                {
                    var errDesc = Crypt32Helper.GetErrorDescription(Kernel32Helper.GetLastError());
                }
            }
            finally
            {

            }
            return found;
        }

        public bool SetProvider(string keyContainerName, string providerName)
        {
            fixed (byte* numPtr1 = Encoding.UTF32.GetBytes(keyContainerName))
            fixed (byte* numPtr2 = Encoding.UTF32.GetBytes(providerName))
            {
                var pvData = new CRYPT_KEY_PROV_INFO()
                {
                    pwszContainerName = (char*)numPtr1,
                    pwszProvName = (char*)numPtr2,
                    dwProvType = 80,
                    dwFlags = 0,
                    cProvParam = 0,
                    rgProvParam = IntPtr.Zero,
                    dwKeySpec = 1
                };
                if (!Crypt32Helper.CertSetCertificateContextProperty(handle, (int)Constants.CERT_KEY_PROV_INFO_PROP_ID, 0, &pvData))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Ошибка привязки ссылки на закрытый ключ к сертификату.  {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }
            }

            return true;
        }

        public CCertificate(byte[] certificateBytes)
        {
            IntPtr newCertificateContext = Crypt32Helper.CertCreateCertificateContext(
                PivotConstants.PKCS_7_OR_X509_ASN_ENCODING,
                certificateBytes,
                (uint)certificateBytes.Length
            );

            if (newCertificateContext == IntPtr.Zero)
            {
                InitEmpty();
            }
            else
            {
                //using var x509cert = new X509Certificate(certificateBytes);
                //KeyAlgorithmOid = x509cert.GetKeyAlgorithm();
                InitFromPtr(newCertificateContext);
            }
        }

        public CCertificate(IntPtr certPtr)
        {
            InitFromPtr(certPtr);
        }

        protected void InitEmpty()
        {
            handle = IntPtr.Zero;
            certContext = null;
            released = false;
            serialNumber = string.Empty;
        }

        protected void InitFromPtr(IntPtr certPtr)
        {
            handle = certPtr;
            if (handle != IntPtr.Zero)
            {
                IntPtr privateKeyUsagePeriodPointer = IntPtr.Zero;
                var oidPtr = Marshal.StringToHGlobalAuto(Constants.szCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode);
                try
                {
                    certContext = new ReadOnlySpan<CryptoProWrapper.Crypto.CERT_CONTEXT>(certPtr.ToPointer(), 1)[0];// Marshal.PtrToStructure<PointerStructures.CERT_CONTEXT>(handle);
                    if (certContext.HasValue)
                    {
                        context = certContext.Value;
                        var certInfo = *certContext.Value.pCertInfo;
                        issuerBytes = PivotFunctionsHelper.GetBytesArrayFromBlob(certInfo.Issuer);
                        subjectBytes = PivotFunctionsHelper.GetBytesArrayFromBlob(certInfo.Subject);
                        Array.Reverse(issuerBytes);
                        Array.Reverse(subjectBytes);
                        var comparisonResult = PivotFunctionsHelper.CompareByteArrays(issuerBytes, subjectBytes);
                        serialNumberBytes = PivotFunctionsHelper.GetBytesArrayFromBlob(certInfo.SerialNumber);
                        notBeforeFiletime = certInfo.NotBefore;
                        notBefore = PivotFunctionsHelper.ConvertFileTime(notBeforeFiletime);
                        notAfterFiletime = certInfo.NotAfter;
                        notAfter = PivotFunctionsHelper.ConvertFileTime(notAfterFiletime);
                        serialNumber = PivotFunctionsHelper.ToHexString(serialNumberBytes);

                        issuer = Encoding.ASCII.GetString(issuerBytes);
                        subject = Encoding.UTF8.GetString(subjectBytes);

                        var authorityInfoExtensionPtr = Crypt32Helper.CertFindExtension(Constants.AuthorityInfoAccessOID, certInfo.cExtension, certInfo.rgExtension);

                        if (authorityInfoExtensionPtr != IntPtr.Zero)
                        {
                            var authorityKeyIdentifierExtension = (CryptoProWrapper.Crypto.CERT_EXTENSION)Marshal.PtrToStructure(authorityInfoExtensionPtr, typeof(CryptoProWrapper.Crypto.CERT_EXTENSION));
                            var authorityInformationAccess = Encoding.UTF8.GetString(authorityKeyIdentifierExtension.Value.ToByteArray());

                            var rootURLMatch = Regex.Match(authorityInformationAccess, @"http.*\.crt");
                            issuerCertURL = rootURLMatch?.Value ?? string.Empty;
                        }

                        var crlDistributionPointExtensionPtr = Crypt32Helper.CertFindExtension(Constants.CRLDistibutionPointOID, certInfo.cExtension, certInfo.rgExtension);

                        if (crlDistributionPointExtensionPtr != IntPtr.Zero)
                        {
                            var crlDistributionPointExtension = (CryptoProWrapper.Crypto.CERT_EXTENSION)Marshal.PtrToStructure(crlDistributionPointExtensionPtr, typeof(CryptoProWrapper.Crypto.CERT_EXTENSION));
                            var crlDistributionPointInfo = Encoding.UTF8.GetString(crlDistributionPointExtension.Value.ToByteArray());

                            var xrlURLMatch = Regex.Match(crlDistributionPointInfo, @"http.*\.crl");
                            crlURL = xrlURLMatch?.Value ?? string.Empty;
                        }

                        var authorityKeyIdentifierExtensionPtr = Crypt32Helper.CertFindExtension(Constants.AuthorityKeyIdentifierOID, certInfo.cExtension, certInfo.rgExtension);

                        if (authorityKeyIdentifierExtensionPtr != IntPtr.Zero)
                        {
                            var authorityKeyIdentifierExtension = (CryptoProWrapper.Crypto.CERT_EXTENSION)Marshal.PtrToStructure(authorityKeyIdentifierExtensionPtr, typeof(CryptoProWrapper.Crypto.CERT_EXTENSION));
                            authorityUniqueIdentifier = authorityKeyIdentifierExtension.Value.ToByteArray();
                        }

                        var subjectKeyIdentifierExtensionPtr = Crypt32Helper.CertFindExtension(Constants.SubjectKeyIdentifierOID, certInfo.cExtension, certInfo.rgExtension);

                        if (subjectKeyIdentifierExtensionPtr != IntPtr.Zero)
                        {
                            var subjectKeyIdentifierExtension = (CryptoProWrapper.Crypto.CERT_EXTENSION)Marshal.PtrToStructure(subjectKeyIdentifierExtensionPtr, typeof(CryptoProWrapper.Crypto.CERT_EXTENSION));
                            subjectUniqueIdentifier = subjectKeyIdentifierExtension.Value.ToByteArray();
                        }

                        var privateKeyUsagePeriodExtensionPtr = Crypt32Helper.CertFindExtension(Constants.szOID_PRIVATEKEY_USAGE_PERIOD, certInfo.cExtension, certInfo.rgExtension);

                        if (privateKeyUsagePeriodExtensionPtr != IntPtr.Zero)
                        {
                            var subjectKeyIdentifierExtension = (CryptoProWrapper.Crypto.CERT_EXTENSION)Marshal.PtrToStructure(privateKeyUsagePeriodExtensionPtr, typeof(CryptoProWrapper.Crypto.CERT_EXTENSION));

                            int cbRequired = 0;

                            if (!Crypt32Helper.CryptDecodeObject(Constants.PKCS_7_OR_X509_ASN_ENCODING, oidPtr,
                                subjectKeyIdentifierExtension.Value.pbData, subjectKeyIdentifierExtension.Value.cbData,
                                0, null, ref cbRequired))
                            {
                                var err = ExceptionHelper.GetLastPInvokeError();
                            }

                            privateKeyUsagePeriodPointer = Marshal.AllocHGlobal(cbRequired);
                            if (!Crypt32Helper.CryptDecodeObject(Constants.PKCS_7_OR_X509_ASN_ENCODING, oidPtr,
                                subjectKeyIdentifierExtension.Value.pbData, subjectKeyIdentifierExtension.Value.cbData,
                                0, (void*)privateKeyUsagePeriodPointer, ref cbRequired))
                            {
                                var err = ExceptionHelper.GetLastPInvokeError();
                            }

                            var info = Marshal.PtrToStructure(privateKeyUsagePeriodPointer, typeof(CPCERT_PRIVATEKEY_USAGE_PERIOD));

                            if (info != null && info is CPCERT_PRIVATEKEY_USAGE_PERIOD)
                            {
                                var structInfo = (CPCERT_PRIVATEKEY_USAGE_PERIOD)info;
                                notBeforeKey = PivotFunctionsHelper.ConvertFileTime(*structInfo.pNotBefore);
                                notAfterKey = PivotFunctionsHelper.ConvertFileTime(*structInfo.pNotAfter);
                            }
                        }
                    }
                }
                catch
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException(err.ErrorMessage, CapiLiteCoreErrors.InternalServerError);
                }
                finally
                {
                    Marshal.FreeHGlobal(oidPtr);
                    if (privateKeyUsagePeriodPointer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(privateKeyUsagePeriodPointer);
                    }
                }
            }

            var certcontext = (CERT_CONTEXT?)Marshal.PtrToStructure(handle, typeof(CERT_CONTEXT));//https://stackoverflow.com/questions/26224471/using-x509certificate-constructor-with-intptr-generates-methodaccessexception

            if (certcontext != null)
            {
                byte[] rawData = new byte[certcontext.Value.cbCertEncoded];
                Marshal.Copy(certcontext.Value.pbCertEncoded, rawData, 0, rawData.Length);
                using var x509cert = new X509Certificate(rawData);
                KeyAlgorithmOid = x509cert.GetKeyAlgorithm();
                HashAlgorithmOid = GetHashOid(KeyAlgorithmOid);
            }
        }

        public bool IsParentFor(ICCertificate cert)
        {
            if (subjectUniqueIdentifier == null || cert.authorityUniqueIdentifier == null) return false;

            var subjectUniqueIdentifierCleaned = subjectUniqueIdentifier.Skip(1).ToArray();//new byte[subjectUniqueIdentifier.Length - 1];
            var authorityUniqueIdentifierCleaned = cert.authorityUniqueIdentifier.Skip(3).ToArray();

            return PivotFunctionsHelper.CompareByteArrays(subjectUniqueIdentifierCleaned, authorityUniqueIdentifierCleaned);
            //return PivotFunctionsHelper.CompareByteArrays(subjectUniqueIdentifier, cert.authorityUniqueIdentifier);
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero && !released)
            {
                released = Crypt32Helper.CertFreeCertificateContext(handle);
            }

            if (released)
            {
                GC.SuppressFinalize(this);
            }
        }

        //~CCertificate()
        //{
        //    Dispose();
        //}

        /// <summary>
        /// Функция получения OID алгоритма хеширования по сертификату
        /// </summary>
        /// <param name="pCert"></param>
        /// <returns></returns>
        private string GetHashOid(string pKeyAlg)
        {
            string oid = string.Empty;

            switch (pKeyAlg)
            {
                case Constants.szOID_CP_GOST_R3410EL:
                    oid = Constants.szOID_CP_GOST_R3411;
                    break;
                case Constants.szOID_CP_GOST_R3410_12_256:
                    oid = Constants.szOID_CP_GOST_R3411_12_256;
                    break;
                case Constants.szOID_CP_GOST_R3410_12_512:
                    oid = Constants.szOID_CP_GOST_R3411_12_512;
                    break;
                default: throw new Exception($"Для алгоритма хеширования данного публичного ключа не найден алгоритм шифрования");

            }
            return oid;
        }
    }
}
