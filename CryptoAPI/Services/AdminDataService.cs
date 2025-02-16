namespace CryptoAPI.Services
{
    public class AdminDataService : IAdminDataService
    {
        private readonly IConfiguration configuration;

        public AdminDataService(IConfiguration _configuration)
        {
            configuration = _configuration;
        }

        public void AddOrUpdateAppSetting<T>(string key, T value)
        {
            try
            {
                var filePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
                string json = File.ReadAllText(filePath);
                dynamic? jsonObj = Newtonsoft.Json.JsonConvert.DeserializeObject(json);

                var sectionPath = key.Split(":")[0];

                if (!string.IsNullOrEmpty(sectionPath))
                {
                    var keyPath = key.Split(":")[1];
                    if (jsonObj != null)
                    {
                        jsonObj[sectionPath][keyPath] = value;
                    }
                }
                else
                {
                    if (jsonObj != null)
                    {
                        jsonObj[sectionPath] = value;
                    }
                }

                string output = Newtonsoft.Json.JsonConvert.SerializeObject(jsonObj, Newtonsoft.Json.Formatting.Indented);
                File.WriteAllText(filePath, output);
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                Console.WriteLine("Error writing app settings");
            }
        }

        public string GetAppSetting()
        {
            try
            {
                var filePath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
                string json = File.ReadAllText(filePath);
                return json;
            }
            catch (Exception ex)
            {
                string logMsg2 = ex.Message;
                Console.WriteLine("Error writing app settings");
                return string.Empty;
            }
        }
    }
}
