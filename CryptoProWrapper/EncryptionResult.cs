namespace CryptoProWrapper
{
    public class EncryptionResult
    {
        /// <summary>
        /// Шифрование прошло успешно
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Результат шифрования
        /// </summary>
        public byte[] EncryptedData { get; set; }

        /// <summary>
        /// Сообщение об ошибке
        /// </summary>
        public string Error { get; set; }
    }
}
