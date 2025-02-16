using Crypto.Interfaces;
using Crypto.Pivot;
using CryptoProWrapper;
using CryptStructure;

namespace Crypto.Entities
{
    public unsafe class CStore : ICStore
    {
        public IntPtr handle { get; private set; }
        public bool released { get; private set; }
        private List<ICCertificate> openCertificates { get; set; }

        public CStore()
        {
            released = true;
            openCertificates = new List<ICCertificate>();
        }

        public CStore(IntPtr hStore)
        {
            handle = hStore;
            released = false;
            openCertificates = new List<ICCertificate>();
        }

        public bool Open(StoreType storeType)
        {
            switch (storeType)
            {
                case StoreType.Memory:
                    bool success = OpenMemoryStore();
                    released = !success;
                    return success;
            }

            return false;
        }

        public bool Add(IntPtr certificatePtr)
        {
            IntPtr addedCertPtr = IntPtr.Zero;
            var result = Crypt32Helper.CertAddCertificateContextToStore(
                handle,
                certificatePtr,
                PivotConstants.CERT_STORE_ADD_REPLACE_EXISTING,
                out addedCertPtr
            );

            var err = Kernel32Helper.GetLastError();

            return result;
        }

        public bool Add(ICCertificate certificate)
        {
            return Add(certificate.handle);
        }

        public bool Add(CryptoProWrapper.Crypto.CERT_CONTEXT certificateStructure)
        {
            return false;
        }

        public bool Remove(ICCertificate certificate)
        {
            return Remove(certificate.handle);
        }

        public bool Remove(IntPtr certificatePtr)
        {
            var result = Crypt32Helper.CertDeleteCertificateFromStore(certificatePtr);

            return result;
        }

        public bool Remove(CryptoProWrapper.Crypto.CERT_CONTEXT certificateStructure)
        {
            return false;
        }

        public List<ICCertificate> GetCertificates()
        {
            //var lastCertificate = new CCertificate();
            IntPtr certHandle = IntPtr.Zero;
            var finished = false;
            var limit = 500;

            while (!finished && limit > 0)
            {
                limit--;
                IntPtr newCertPtr = Crypt32Helper.CertEnumCertificatesInStore(
                    handle,
                    certHandle
                );

                if (newCertPtr != IntPtr.Zero)
                {
                    var lastCertificate = new CCertificate(newCertPtr);
                    openCertificates.Add(lastCertificate);
                    certHandle = lastCertificate.handle;
                }
                else
                {
                    finished = true;
                }
            }

            return openCertificates;
        }

        public bool AddCRL(ICRL crl)
        {
            var result = Crypt32Helper.CertAddCRLContextToStore(handle, crl.handle, Constants.CERT_STORE_ADD_REPLACE_EXISTING, 0);

            return result;
        }

        public bool RemoveCRL(ICRL crl)
        {
            var result = Crypt32Helper.CertDeleteCRLFromStore(crl.handle);

            return result;
        }

        public List<ICRL> GetCRLs()
        {
            var result = new List<ICRL>();

            CRL lastCRL = new CRL();

            var finished = false;
            var limit = 500;

            while (!finished && limit > 0)
            {
                limit--;

                IntPtr newCRLPtr = Crypt32Helper.CertEnumCRLsInStore(
                    handle,
                    lastCRL.handle
                );

                if (newCRLPtr != IntPtr.Zero)
                {
                    lastCRL = new CRL(newCRLPtr);
                    result.Add(lastCRL);
                }
                else
                {
                    finished = true;
                }
            }

            return result;
        }

        private bool OpenMemoryStore()
        {
            bool success = false;
            released = true;
            handle = Crypt32Helper.CertOpenStore(
                (IntPtr)PivotConstants.CERT_STORE_PROV_MEMORY,
                PivotConstants.PKCS_7_OR_X509_ASN_ENCODING,
                IntPtr.Zero,
                PivotConstants.CERT_STORE_CREATE_NEW_FLAG,
                IntPtr.Zero);

            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Хранилище не создано по непонятным причинам.");
            }
            else
            {
                success = true;
                released = false;
            }

            return success;
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero && !released)
            {
                released = Crypt32Helper.CertCloseStore(handle, 0);
            }

            foreach (var openCert in openCertificates)
            {
                Crypt32Helper.CertFreeCertificateContext(openCert.handle);
            }

            if (released) GC.SuppressFinalize(this);
        }

        public bool OpenSystem(StoreNameType storeNameType, uint dwFlags = PivotConstants.CERT_SYSTEM_STORE_LOCAL_MACHINE | PivotConstants.CERT_STORE_MAXIMUM_ALLOWED_FLAG | PivotConstants.CERT_STORE_OPEN_EXISTING_FLAG)
        {
            string name = string.Empty;
            switch (storeNameType)
            {
                case StoreNameType.Root:
                    name = "Root";
                    break;
                case StoreNameType.My:
                    name = "MY";
                    break;
                case StoreNameType.CA:
                    name = "CA";
                    break;
            }

            uint searchFlag = OSHelper.fIsLinux ? Constants.CERT_STORE_PROV_SYSTEM_A : Constants.CERT_STORE_PROV_SYSTEM_W;
            handle = Crypt32Helper.CertOpenStore(
                new IntPtr((int)searchFlag),
                (int)Constants.PKCS_7_OR_X509_ASN_ENCODING,
                IntPtr.Zero,
                dwFlags,
                name
            );

            var err = Kernel32Helper.GetLastError();


            if (handle != IntPtr.Zero) released = false;

            return !released;
        }

        public void SystemLinux(IntPtr hProv)
        {
            handle = Crypt32Helper.CertOpenSystemStore(
                hProv, // HCRYPTPROV
                "My"
            );
        }

        ~CStore()
        {
            Dispose();
        }
    }
}
