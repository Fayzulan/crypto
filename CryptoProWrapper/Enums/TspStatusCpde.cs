namespace CryptoProWrapper.Enums
{
    /// <summary>
    /// Статус ответа службы штампов времени
    /// </summary>
    public enum TspStatusCpde
    {
        /// <summary>
        /// штамп выдан
        /// </summary>
        SuccessStump = 0,

        /// <summary>
        /// штамп выдан с ограничениями
        /// </summary>
        LimiedSuccessStamp = 1,

        /// <summary>
        /// в выдаче штампа отказано
        /// </summary>
        FailureStamp = 2,

        /// <summary>
        /// запрос принят на рассмотрение
        /// </summary>
        WaitStamp = 3,

        /// <summary>
        /// revocationWarning
        /// </summary>
        RevocationWarningStamp = 4,

        /// <summary>
        /// Неизвестная ошибка
        /// </summary>
        ErrorStamp = 999
    }
}
