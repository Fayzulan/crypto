using CryptoDto.RequestDTO;
using CryptoProWrapper;

namespace CryptoAPI.Services
{
    public interface ICryptoService
    {
        public CryptoContainer GetContainer(CryptoContainerRequestDto signCadesDTO, bool checkPinHashCode = false, string? pinHashCode = null);
    }
}
