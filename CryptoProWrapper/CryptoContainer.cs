namespace CryptoProWrapper
{
    public class CryptoContainer
    {
        /// <summary>
        /// Имя контейнера
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Код доступа к зарытому ключу
        /// </summary>
        public string Pin { get; set; }

        /// <summary>
        /// Имя используемого поставщика служб CSP
        /// </summary>
        public string ProviderName { get; set; }

        /// <summary>
        /// Тип поставщика
        /// </summary>
        public int ProviderType { get; set; }
    }
}
