namespace Crypto.Interfaces
{
    public interface ICCertificate : ICEntity
    {
        public bool HasPersistedPrivateKey { get; }
        public bool HasEphemeralPrivateKey { get; }
        public bool ContainsPrivateKey { get; }
        public CryptoProWrapper.Crypto.CERT_CONTEXT context { get; }
        public string serialNumber { get; }
        public byte[] serialNumberBytes { get; }
        public string issuer { get; }
        public byte[] issuerBytes { get; }
        public byte[] subjectBytes { get; }
        public byte[] authorityUniqueIdentifier { get; }
        public byte[] subjectUniqueIdentifier { get; }
        public /*PointerStructures.FILETIME*/System.Runtime.InteropServices.ComTypes.FILETIME notBeforeFiletime { get; }
        public DateTime notBefore { get; }
        public /*PointerStructures.FILETIME*/System.Runtime.InteropServices.ComTypes.FILETIME notAfterFiletime { get; }
        public DateTime notAfter { get; }
        public DateTime? notBeforeKey { get; }
        public DateTime? notAfterKey { get; }
        public bool isPrivateKeyExpired { get; }
        public string issuerUniqueId { get; }
        public string issuerCertURL { get; }
        public string crlURL { get; }
        public bool isSelfSigned { get; }
        public bool IsParentFor(ICCertificate cert);
    }
}
