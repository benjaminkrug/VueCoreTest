using System.Threading.Tasks;

namespace AuthServices
{
    public interface IAdminService
    {
        Task<bool> AllowAdminUserCreationAsync();
    }
}