namespace Crypto.Interfaces
{
    public interface ICEntity : IDisposable
    {
        IntPtr handle { get; }
        bool released { get; }
    }
}
