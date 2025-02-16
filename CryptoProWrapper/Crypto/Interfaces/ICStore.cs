using Crypto.Pivot;

namespace Crypto.Interfaces
{
    public interface ICStore : ICEntity
    {
        public bool Open(StoreType storeType);
        public bool OpenSystem(StoreNameType storeNameType,
             uint dwFlags = PivotConstants.CERT_SYSTEM_STORE_LOCAL_MACHINE | PivotConstants.CERT_STORE_MAXIMUM_ALLOWED_FLAG | PivotConstants.CERT_STORE_OPEN_EXISTING_FLAG);
        public bool Add(ICCertificate certificate);
        public bool Add(IntPtr certificatePtr);
        public bool Add(CryptoProWrapper.Crypto.CERT_CONTEXT certificateStructure);
        public bool AddCRL(ICRL crl);
        public bool Remove(ICCertificate certificate);
        public bool Remove(IntPtr certificatePtr);
        public bool Remove(CryptoProWrapper.Crypto.CERT_CONTEXT certificateStructure);
        public bool RemoveCRL(ICRL crl);
        public List<ICCertificate> GetCertificates();
        public List<ICRL> GetCRLs();
        public void SystemLinux(IntPtr hProv);
    }
}
