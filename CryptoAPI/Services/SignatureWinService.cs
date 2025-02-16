using CryptoDto.Enums;
using CryptoDto.RequestDTO.Sign;
using CryptoProWrapper;
using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetSignature;
using CryptoProWrapper.SignatureVerification;

namespace CryptoAPI.Services
{
    public class SignatureWinService : CryptoService, ISignatureService
    {
        public CryptoProvider cryptoProvider { get; set; }

        public SignatureWinService(
            IGetCadesSignature getCadesSignature,
            IGetXadesSignature getXadesSignature,
            IValidateCadesSignature cadesVerify,
            IValidateXadesSignature xadesVerify) : base()
        {
            cryptoProvider = new CryptoProvider(getCadesSignature, getXadesSignature, cadesVerify, xadesVerify);
        }

        public SignatureCreateResult TestSignCades(byte[] data, bool detachedSignature, APICadesFormat apiSignatureFormat)
        {
            var signatureCreateResult = new SignatureCreateResult();

            try
            {
                CadesFormat signatureFormat = (CadesFormat)apiSignatureFormat;
                CryptoContainer container = new CryptoContainer
                {
                    Pin = "0000",
                    ProviderType = 80,
                    //Name = "\\\\.\\HDIMAGE\\1c8eaa6e8-be8e-715b-e154-9744da13a22" // Bob L
                    Name = "\\\\.\\REGISTRY\\1c8eaa6e8-be8e-715b-e154-9744da13a22" // Bob L
                };
                signatureCreateResult = cryptoProvider.GetCadesSignature(data, container, detachedSignature, signatureFormat);
                return signatureCreateResult;
            }
            catch (CapiLiteCoreException ex)
            {
                signatureCreateResult.Error = ex.Message;
                string logMsg1 = ex.Message;
            }
            catch (CryptoAPIException ex)
            {
                signatureCreateResult.Error = ex.Message;
                string logMsg2 = ex.Message;
            }
            catch (Exception ex)
            {
                string logMsg3 = ex.Message;
                throw new Exception(ex.Message);
            }

            return signatureCreateResult;
        }

        public SignatureCreateResult TestSignXades(byte[] data, APIXadesType xadesType, APIXadesFormat signatureFormat)
        {
            var signatureCreateResult = new SignatureCreateResult();

            string fileNameWithPath = string.Empty;
            string fileName = $"{Guid.NewGuid().ToString()}.xml";// "file.xml";
            string signatureTemplateFileName = $"{Guid.NewGuid().ToString()}.xml";// "signature_template.xml";
            string finalTemplatePath = string.Empty;

            try
            {
                var dataToBeSigned = data;
                CryptoContainer container = new CryptoContainer
                {
                    Pin = "0000",
                    ProviderType = 80,
                    //Name = "\\\\.\\HDIMAGE\\1c8eaa6e8-be8e-715b-e154-9744da13a22" // Bob L
                    Name = "\\\\.\\REGISTRY\\1c8eaa6e8-be8e-715b-e154-9744da13a22" // Bob L
                };


                // ToDo: TEMPLATE
                //if (xadesType == APIXadesType.TEMPLATE)
                //{
                //    string rootPath = "Xades";

                //    var templateBuilderParams = new XMLDSigBuilderParams();
                //    templateBuilderParams.signatureTemplatePath = $"{rootPath}/detached_pattern.xml";
                //    //templateBuilderParams.dataToBeSignedPath = $"{rootPath}/{fileName}";
                //    templateBuilderParams.signatureType = XadesSignatureType.ExternallyDetached;
                //    templateBuilderParams.nodeToBeSignedXPath = "/ns:Envelope/ns:Data";
                //    templateBuilderParams.fileName = fileName;
                //    templateBuilderParams.finalTemplatePath = $"{rootPath}/{signatureTemplateFileName}";
                //    finalTemplatePath = templateBuilderParams.finalTemplatePath;
                //    fileNameWithPath = templateBuilderParams.fileName;
                //    //fileNameWithPath = $"{templateBuilderParams.xadesLibPath}/{templateBuilderParams.fileName}";
                //    templateBuilderParams.dataToBeSignedPath = fileNameWithPath;
                //    var templateBuilder = new XMLDSigTemplateBuilder();
                //    File.WriteAllBytes(fileNameWithPath, data);
                //    templateBuilder.BuildTemplate(templateBuilderParams);
                //    dataToBeSigned = File.ReadAllBytes(templateBuilderParams.finalTemplatePath);
                //}

                XadesType xadesType1 = (XadesType)xadesType;
                XadesFormat signatureFormat1 = (XadesFormat)signatureFormat;
                signatureCreateResult = cryptoProvider.GetXadesSignature(dataToBeSigned, container, xadesType1, signatureFormat1);
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw new Exception(ex.Message);
            }
            finally
            {
                // ToDo: TEMPLATE
                //if (xadesType == APIXadesType.TEMPLATE)
                //{
                //    File.Delete(fileNameWithPath);
                //    File.Delete(finalTemplatePath);
                //}
            }

            return signatureCreateResult;
        }

        public SignatureCreateResult SignCades(SignCadesDTO signCadesDTO)
        {
            try
            {
                byte[] ContentByteArray = Convert.FromBase64String(signCadesDTO.Content);
                CadesFormat signatureFormat = (CadesFormat)signCadesDTO.SignatureFormat;
                CryptoContainer container = GetContainer(signCadesDTO, true, signCadesDTO.PinHashCode);
                SignatureCreateResult signatureCreateResult = cryptoProvider.GetCadesSignature(ContentByteArray, container, signCadesDTO.IsDetached, signatureFormat);
                return signatureCreateResult;
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (CryptoAPIException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }
        }

        public SignatureValidationResult ValidateCadesSignature(byte[] signMessage, APICadesFormat apiSignatureFormat, byte[]? data)
        {
            var result = new SignatureValidationResult();

            try
            {
                CadesFormat signatureFormat = (CadesFormat)apiSignatureFormat;
                result = cryptoProvider.VerifyCadesSignature(signMessage, data, signatureFormat);
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }

            return result;
        }

        public SignatureCreateResult SignXades(SignXadesDTO signXadesDTO)
        {
            var signatureCreateResult = new SignatureCreateResult();

            // ToDo: TEMPLATE
            //string fileNameWithPath = string.Empty;
            //string fileName = $"{Guid.NewGuid().ToString()}.xml";// "file.xml";
            //string signatureTemplateFileName = $"{Guid.NewGuid().ToString()}.xml";// "signature_template.xml";
            //string finalTemplatePath = string.Empty;

            try
            {
                byte[] ContentByteArray = Convert.FromBase64String(signXadesDTO.Content);
                var dataToBeSigned = ContentByteArray;
                CryptoContainer container = GetContainer(signXadesDTO, true, signXadesDTO.PinHashCode);

                // ToDo: TEMPLATE
                //if (signXadesDTO.XadesType == APIXadesType.TEMPLATE)
                //{
                //    string rootPath = "Xades";

                //    var templateBuilderParams = new XMLDSigBuilderParams();
                //    templateBuilderParams.signatureTemplatePath = $"{rootPath}/detached_pattern.xml";
                //    //templateBuilderParams.dataToBeSignedPath = $"{rootPath}/{fileName}";
                //    templateBuilderParams.signatureType = XadesSignatureType.ExternallyDetached;
                //    templateBuilderParams.nodeToBeSignedXPath = "/ns:Envelope/ns:Data";
                //    templateBuilderParams.fileName = fileName;
                //    templateBuilderParams.finalTemplatePath = $"{rootPath}/{signatureTemplateFileName}";
                //    finalTemplatePath = templateBuilderParams.finalTemplatePath;
                //    fileNameWithPath = templateBuilderParams.fileName;
                //    //fileNameWithPath = $"{templateBuilderParams.xadesLibPath}/{templateBuilderParams.fileName}";
                //    templateBuilderParams.dataToBeSignedPath = fileNameWithPath;
                //    var templateBuilder = new XMLDSigTemplateBuilder();
                //    File.WriteAllBytes(fileNameWithPath, ContentByteArray);
                //    templateBuilder.BuildTemplate(templateBuilderParams);
                //    dataToBeSigned = File.ReadAllBytes(templateBuilderParams.finalTemplatePath);
                //}

                XadesType xadesType = (XadesType)signXadesDTO.XadesType;
                XadesFormat signatureFormat = (XadesFormat)signXadesDTO.SignatureFormat;
                signatureCreateResult = cryptoProvider.GetXadesSignature(dataToBeSigned, container, xadesType, signatureFormat);
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }
            finally
            {
                // ToDo: TEMPLATE
                //if (signXadesDTO.XadesType == APIXadesType.TEMPLATE)
                //{
                //    File.Delete(fileNameWithPath);
                //    File.Delete(finalTemplatePath);
                //}
            }

            return signatureCreateResult;
        }

        public SignatureValidationResult ValidateXadesSignature(byte[] signMessage, APIXadesFormat apiSignatureFormat, byte[]? sourceMessage, APIXadesType apiXadesType)
        {
            try
            {
                // ToDo: TEMPLATE
                //if (apiXadesType == APIXadesType.TEMPLATE)
                //{
                //    if (sourceMessage == null)
                //    {
                //        throw new CryptoAPIException("Не переданы исходные данные");
                //    }

                //    var templateBuilderParams = new XMLDSigBuilderParams();
                //    var xDoc = new XmlDocument();
                //    using var ms = new MemoryStream(signMessage);
                //    xDoc.Load(ms);

                //    XmlNamespaceManager nsmgr = new XmlNamespaceManager(xDoc.NameTable);
                //    nsmgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                //    XmlNode? item = xDoc.SelectSingleNode("//ds:Reference[1]", nsmgr);

                //    if (item == null || item.Attributes == null)
                //    {
                //        throw new Exception("Не удалось получить название файла, содержащего исходные данные.");
                //    }

                //    var attribute = item.Attributes["URI"];

                //    if (attribute == null)
                //    {
                //        throw new Exception("Не удалось получить название файла, содержащего исходные данные.");
                //    }

                //    string fileNameWithPath = attribute.Value;
                //    //fileNameWithPath = $"{templateBuilderParams.xadesLibPath}/{attribute.Value}";
                //    File.WriteAllBytes(fileNameWithPath, sourceMessage);
                //}

                XadesFormat signatureFormat = (XadesFormat)apiSignatureFormat;
                SignatureValidationResult result = cryptoProvider.VerifyXadesSignature(signMessage, sourceMessage, signatureFormat);

                return result;
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }
            finally
            {
                // ToDo: TEMPLATE
                //if (apiXadesType == APIXadesType.TEMPLATE)
                //{
                //    File.Delete(fileNameWithPath);
                //}
            }
        }

        public List<KeyContainer> GetAllKeyContainers()
        {
            var keyContainers = new List<KeyContainer>();

            try
            {
                keyContainers = cryptoProvider.GetAllKeyContainers();
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (CryptoAPIException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }

            return keyContainers;
        }
    }
}
