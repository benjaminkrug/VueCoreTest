namespace Identity.AuthService.Services
{
    public interface IUserServices
    {
        bool RegisterUser(string username, Webapp.Controllers.KeyDto pass, string privateKeyBase64);
        string GetKeyForUser(string username);
    }
}