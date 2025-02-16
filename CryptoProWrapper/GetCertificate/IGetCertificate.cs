using Crypto.Interfaces;
using System.Security.Cryptography.X509Certificates;

namespace CryptoProWrapper
{
    public interface IGetCertificate
    {
        byte[]? GetCertificateFromContainer(CryptoContainer container);
        string GetCertSerialNumberFromSignature(byte[] signarureData);
        unsafe ICCertificate? GetCertFromCadesSignature(byte[] signarureData);
        unsafe ICCertificate? GetCertFromXadesSignature(byte[] signarureData);

        byte[]? GetCertificateByCryptAcquireContext(nint hProv);

        X509Certificate GetCertificateFromPfx(string path);
    }
}
