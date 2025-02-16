namespace CryptoProWrapper.GetTspToken
{
    public interface IGetTspToken
    {
        byte[] GetTspToken(string TSPAddress, List<byte[]> texts, string hashOid, out uint tokenSize);
    }
}
