namespace CryptoProWrapper
{
    /// <summary>
    /// Результат проверки подписи
    /// </summary>
    public class SignatureValidationResult
    {
        /// <summary>
        /// Поверена целостность подписи
        /// </summary>
        public bool IsSignatureValid { get; set; }

        /// <summary>
        /// Формат подписи
        /// </summary>
        public string SignatureFormat { get; set; }

        /// <summary>
        /// Сообщение об ошибке
        /// </summary>
        public string Error { get; set; }

        /// <summary>
        /// Открепленная подпись?
        /// </summary>
        public bool IsDetachedSignature { get; set; }
    }
}
