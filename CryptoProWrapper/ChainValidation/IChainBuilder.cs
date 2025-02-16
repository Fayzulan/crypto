namespace CryptoAPI
{
    public interface IChainBuilder
    {
        public IntPtr Build(IntPtr certificate, ChainValidationParameters chainValidationParameters);
    }
}
