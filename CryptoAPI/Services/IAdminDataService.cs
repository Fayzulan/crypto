namespace CryptoAPI.Services
{
    public interface IAdminDataService
    {
        public void AddOrUpdateAppSetting<T>(string key, T value);
        public string GetAppSetting();
    }
}
