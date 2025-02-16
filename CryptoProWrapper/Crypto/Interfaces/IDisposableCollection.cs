namespace CryptoProWrapper.Crypto.Interfaces
{
    internal interface IDisposableCollection<T> : IEnumerable<T>, IDisposable where T : IDisposable
    {
        T this[int index] { get; }
        public void AddElem(T elem);
    }
}
