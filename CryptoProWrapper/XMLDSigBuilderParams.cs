namespace CryptoProWrapper
{
    public class XMLDSigBuilderParams
    {
        public string fileName;
        public string dataToBeSignedPath;
        public string signatureTemplatePath;
        public string finalTemplatePath;
        public XadesSignatureType signatureType;
        public string nodeId;
        public string nodeToBeSignedXPath;
        public string xadesLibPath = OSHelper.LibsPath;
    }
}
