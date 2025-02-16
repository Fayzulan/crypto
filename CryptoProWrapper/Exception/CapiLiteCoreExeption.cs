namespace CryptoProWrapper
{
    public class CapiLiteCoreException : Exception
    {
        /// <summary>
        /// Код ошибки (300+)
        /// </summary>
        public CapiLiteCoreErrors ErrorCode { get; set; }
        public CapiLiteCoreException(string message, CapiLiteCoreErrors ErrorCode) : base(message)
        {
            this.ErrorCode = ErrorCode;
        }
    }
}
