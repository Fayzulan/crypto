using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetSignature;
using CryptoProWrapper.SignatureVerification;

namespace CryptoProWrapper
{
    public class CryptoProvider
    {
        private IGetCadesSignature _getCadesSignature;
        private IGetXadesSignature _getXadesSignature;
        private IValidateCadesSignature _cadesVerify;
        private IValidateXadesSignature _xadesVerify;

        public CryptoProvider(
            IGetCadesSignature getCadesSignature,
            IGetXadesSignature getXadesSignature,
            IValidateCadesSignature verify,
            IValidateXadesSignature xadesVerify)
        {
            _getCadesSignature = getCadesSignature;
            _getXadesSignature = getXadesSignature;
            _cadesVerify = verify;
            _xadesVerify = xadesVerify;
        }

        public SignatureCreateResult GetCadesSignature(byte[] data, CryptoContainer conteiner, bool detachedSignature, CadesFormat signatureFormat)
        {
            bool includeCrl = signatureFormat == CadesFormat.CadesA || signatureFormat == CadesFormat.CadesXLongType1;
            SignatureCreateResult signatureCreateResult = _getCadesSignature.GetCadesBesSignature(conteiner, data, detachedSignature, includeCrl);

            if (signatureCreateResult.Success && signatureFormat != CadesFormat.CadesBes)
            {
                _getCadesSignature.EnchanceSignature(signatureCreateResult, signatureFormat);
            }

            return signatureCreateResult;
        }

        public SignatureCreateResult GetXadesSignature(byte[] data, CryptoContainer conteiner, XadesType xadesType, XadesFormat signatureFormat)
        {
            SignatureCreateResult signatureCreateResult = _getXadesSignature.GetXadesSignature(conteiner, data, xadesType, signatureFormat);
            return signatureCreateResult;
        }

        public SignatureValidationResult VerifyCadesSignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat)
        {
            return _cadesVerify.VerifySignature(signMessage, data, signatureFormat);
        }

        public SignatureValidationResult VerifyXadesSignature(byte[] signMessage, byte[]? data, XadesFormat signatureFormat)
        {
            return _xadesVerify.VerifySignature(signMessage, data, signatureFormat);
        }

        public bool CheckLibrary(string libName)
        {
            try
            {
                switch (libName)
                {
                    case OSHelper.ADVAPI32:
                        ADVAPI32Helper.CryptDestroyHash(IntPtr.Zero);
                        return true;
                    case OSHelper.CADES:
                        CadesHelper.CadesFreeBlob(IntPtr.Zero);
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public List<KeyContainer> GetAllKeyContainers()
        {
            return _getCadesSignature.GetAllKeyContainers();
        }
    }
}

