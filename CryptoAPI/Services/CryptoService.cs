using CryptoDto.RequestDTO;
using CryptoProWrapper;
using System.Security.Cryptography;
using System.Text;

namespace CryptoAPI.Services
{
    public class CryptoService : ICryptoService
    {

        /// <summary>
        /// Получение информации о контейнере по параметрам сертификата
        /// </summary>
        /// <param name="signCadesDTO"></param>
        /// <param name="pinHashCode"></param>
        /// <param name="checkPinHashCode"></param>
        /// <returns></returns>
        public CryptoContainer GetContainer(CryptoContainerRequestDto signCadesDTO, bool checkPinHashCode = false, string? pinHashCode = null)
        {
            var providerType = 80;

            if (checkPinHashCode)
            {
                string pinHashCodeVault = GetHash("пин код контейнера");

                if (!string.Equals(pinHashCodeVault, pinHashCode))
                {
                    string logMsg1 = "Указан неверный пин.";
                    throw new CryptoAPIException("Указан неверный пин.", CryptoAPIErrors.BadRequest);
                }
            }

            if (!Int32.TryParse("тип провайдера", out providerType))
            {
                string logMsg2 = "Не удалось получить тип провайдера.";
                throw new CryptoAPIException("Не удалось получить тип провайдера.", CryptoAPIErrors.InternalServerError);
            }

            return new CryptoContainer
            {
                Pin = "пин контейнера",
                ProviderType = providerType,
                Name = "путь к контейнеру"
            };

            //return new CryptoContainer
            //{
            //    Pin = "0000",
            //    //Name = "\\\\.\\HDIMAGE\\5917ab78a-ab75-51e0-7ea1-8fb41116607" // Ben L
            //    //ProviderName = "Crypto-Pro GOST R 34.10-2001 KC1 CSP",
            //    ProviderType = 80,
            //    //Name = "\\\\.\\REGISTRY\\f44843a20-2133-dd82-e6ce-120fb5578ad" // Gor
            //    //Name = "\\\\.\\REGISTRY\\afa21782-c2aa-4447-9d08-d4a16070abe6" // Казаков Артем Павлович (cert2-1.pfx)
            //    //Name = "\\\\.\\REGISTRY\\7fa2e88e-e3ab-458e-bb34-363f76b9f9a3" // Казаков Артем Павлович (cert1-1.pfx) pin = 1
            //    //Name = "HDIMAGE\\\\afa21782.000\\7027"
            //    Name = "\\\\.\\HDIMAGE\\1c8eaa6e8-be8e-715b-e154-9744da13a22" // Bob L
            //    //Name = "\\\\.\\HDIMAGE\\8408993e3-7c13-3604-2912-f60a28d2508" // Ruslan L
            //    //Name = "\\\\.\\REGISTRY\\5917ab78a-ab75-51e0-7ea1-8fb41116607" // Ben
            //    //Name = "\\\\.\\FAT12_D\\5917ab78a-ab75-51e0-7ea1-8fb41116607" // Ben W
            //    //Name = "\\\\.\\HDIMAGE\\5917ab78a-ab75-51e0-7ea1-8fb41116607" // Ben L
            //    //Name = "\\\\.\\HDIMAGE\\afa21782-c2aa-4447-9d08-d4a16070abe6"
            //    //Name = "\\\\.\\HDIMAGE\\afa21782-c2aa-4447-9d08-d4a16070abe6"
            //    //Name = "\\\\.\\HDIMAGE\\7fa2e88e-e3ab-458e-bb34-363f76b9f9a3"// Казаков Артем Павлович (cert1-1.pfx)
            //    //Name = "\\\\.\\HDIMAGE\\afa21782.000\\7027"
            //    // Name = "\\\\.\\HDIMAGE\\\\dbdc2368.000\\B0B9"
            //};

            //return "\\\\.\\FAT12_D\\e412889ca-b880-4c88-527e-237588a65f4"; //на диске
            //return "e412889ca-b880-4c88-527e-237588a65f4";// в реестре
        }

        private string GetHash(string pin)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(pin));

                // Convert byte array to a string
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
