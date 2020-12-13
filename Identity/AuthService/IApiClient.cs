using System.Collections.Generic;
using System.Threading.Tasks;

namespace FrontEnd.Services
{
    public interface IApiClient
    {
        Task<string> GetUsersAsync();
        Task<string> GetBackendTest();
    }
}