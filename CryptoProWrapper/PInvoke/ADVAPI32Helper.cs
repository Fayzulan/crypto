using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    public class ADVAPI32Helper
    {
        /// <summary>
        /// Получение дескриптора определенного контейнера ключей в определенном поставщике служб шифрования (CSP)
        /// </summary>
        /// <param name="hProv">Указатель на дескриптор CSP</param>
        /// <param name="pszContainer">Имя контейнера ключа</param>
        /// <param name="pszProvider">Имя используемого поставщика служб CSP</param>
        /// <param name="dwProvType">Тип поставщика для получения</param>
        /// <param name="dwFlags">Поведение метода</param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "CryptAcquireContext" + OSHelper.OSPosfix)]
        internal static extern bool CryptAcquireContext(out nint hProv, string? pszContainer, string? pszProvider, uint dwProvType, uint dwFlags);

        /// <summary>
        /// Извлекает дескриптор пар открытого и закрытого ключей пользователя
        /// </summary>
        /// <param name="hProv">Дескриптор поставщика служб шифрования (CSP)</param>
        /// <param name="dwKeySpec">Определяет закрытый ключ для использования из контейнера ключей</param>
        /// <param name="phUserKey">Указатель на дескриптор извлеченных ключей</param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptGetUserKey(nint hProv, int dwKeySpec, out nint phUserKey);

        /// <summary>
        /// Извлекает данные, управляющие операциями ключа.
        /// </summary>
        /// <param name="hKey">Дескриптор запрашиваемого ключа</param>
        /// <param name="dwParam">Тип выполняемого запроса</param>
        /// <param name="pbData">Указатель на буфер, который получает данные.</param>
        /// <param name="pdwDataLen">Размер буфера в байтах</param>
        /// <param name="dwFlags"></param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, SetLastError = true)]
        internal static extern bool CryptGetKeyParam(nint hKey, uint dwParam, [Out] byte[]? pbData, [In, Out] ref uint pdwDataLen, uint dwFlags);

        /// <summary>
        /// Безопасно экспортирует криптографический ключ или пару ключей от поставщика
        /// </summary>
        /// <param name="hKey">Дескриптор ключа, который нужно экспортировать</param>
        /// <param name="hExpKey">Дескриптор криптографического ключа целевого пользователя</param>
        /// <param name="dwBlobType">Тип ключа BLOB для экспорта</param>
        /// <param name="dwFlags">Задает дополнительные параметры для функции</param>
        /// <param name="pbData"></param>
        /// <param name="pdwDataLen"></param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool CryptExportKey(IntPtr hKey, IntPtr hExpKey, int dwBlobType, int dwFlags, byte[] pbData, ref int pdwDataLen);

        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool CryptReleaseContext(IntPtr hProv, int dwFlags);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, [In, Out] byte[] pbData, ref uint dwDataLen, uint dwFlags);

        //[DllImport(OSHelper.ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        //internal static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, [MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern bool CryptGenKey(IntPtr hProv, uint Algid, uint dwFlags, ref IntPtr phKey);

        /// <summary>
        /// Создает криптографические ключи сеанса
        /// </summary>
        /// <param name="hProv">Дескриптор CSP</param>
        /// <param name="Algid">Алгоритм симметричного шифрования, для которого создается ключ</param>
        /// <param name="hBaseData">Дескриптор хэш-объекта , которому были предоставлены точные базовые данные</param>
        /// <param name="dwFlags">Указывает тип создаваемого ключа</param>
        /// <param name="phKey">Дескриптор закрытого ключа</param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptDeriveKey(IntPtr hProv, uint Algid, IntPtr hBaseData, uint dwFlags, ref IntPtr phKey);

        /// <summary>
        /// Customizes the operations of a cryptographic service provider (CSP). This function is commonly used to set a security descriptor on the key container associated with a CSP to control access to the private keys in that key container.
        /// </summary>
        /// <param name="hProv">The handle of a CSP for which to set values. </param>
        /// <param name="dwParam">Specifies the parameter to set.</param>
        /// <param name="pvData">A pointer to a data buffer that contains the value to be set as a provider parameter. The form of this data varies depending on the dwParam value.</param>
        /// <param name="dwFlags">If dwParam contains PP_KEYSET_SEC_DESCR, dwFlags contains the SECURITY_INFORMATION applicable bit flags, as defined in the Platform SDK.</param>
        /// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE). For extended error information, call GetLastError.</returns>
        /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptsetprovparam</remarks>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptSetProvParam(
            [In] nint hProv,
            [In] uint dwParam,
            [In] nint pvData,
            [In] uint dwFlags
        );

        /// <summary>
        /// Создание хеш-объекта
        /// </summary>
        /// <param name="hProv">Дескриптор CSP</param>
        /// <param name="algId">Хэш-алгоритм</param>
        /// <param name="hKey">Ключ для хэша, если тип хэш-алгоритма является хэш-хэшом с ключом. Иначе 0</param>
        /// <param name="dwFlags">0</param>
        /// <param name="phHash">Дескриптор хэша</param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptCreateHash(nint hProv, uint algId, nint hKey, uint dwFlags, ref nint phHash);

        // Импорт библиотеки advapi32.dll
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptHashData(IntPtr hHash, byte[] pbData, int dwDataLen, int dwFlags);

        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);

        #region Шифрование
        /// <summary>
        /// Шифрование
        /// </summary>
        /// <param name="hKey"></param>
        /// <param name="hHash"></param>
        /// <param name="Final">Логическое значение, указывающее, является ли этот раздел последним в шифруемом ряду. Параметр Final имеет значение TRUE для последнего или единственного блока и значение FALS</param>
        /// <param name="dwFlags">Следующее значение dwFlags определено, но зарезервировано для использования в будущем.</param>
        /// <param name="pbData">Указатель на буфер, содержащий зашифрованный открытый текст. Открытый текст в этом буфере перезаписывается с помощью зашифрованного текста , созданного этой функцией.</param>
        /// <param name="pdwDataLen">Указатель на значение DWORD , которое в записи содержит длину в байтах открытого текста в буфере pbData .</param>
        /// <param name="dwBufLen"></param>
        /// <returns></returns>
        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptEncrypt(IntPtr hKey, IntPtr hHash, bool Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen, uint dwBufLen);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true)]
        internal static extern bool CryptGenKey(IntPtr hProv, int Algid, int dwFlags, out IntPtr phKey);

        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto)]
        internal static extern bool CryptDestroyHash(IntPtr hHash);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptDecrypt(IntPtr hKey, IntPtr hHash, int Final, uint dwFlags, byte[] pbData, ref uint pdwDataLen);

        [DllImport(OSHelper.ADVAPI32, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptGenRandom(IntPtr hProv, uint dwLen, byte[] pbBuffer);

        [DllImport(OSHelper.ADVAPI32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptSetKeyParam(
            IntPtr hKey,
            uint dwParam,
            byte[] pbData,
            uint dwFlags
        );
        #endregion
    }
}
