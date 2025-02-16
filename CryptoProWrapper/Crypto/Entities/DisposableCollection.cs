using CryptoProWrapper.Crypto.Interfaces;
using System.Collections;

namespace CryptoProWrapper.Crypto.Entities
{
    public class DisposableCollection<T> : IDisposableCollection<T> where T : IDisposable
    {
        List<T> collection;

        public DisposableCollection()
        {
            collection = new List<T>();
        }

        public T this[int index]
        {
            get
            {
                return collection[index];
            }
        }

        public void AddElem(T elem)
        {
            collection.Add(elem);
        }

        public void Dispose()
        {
            foreach (var item in collection)
            {
                item.Dispose();
            }
        }

        public IEnumerator<T> GetEnumerator()
        {
            return collection.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return collection.GetEnumerator();
        }
    }
}
