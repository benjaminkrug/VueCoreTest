namespace Webapp.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.Linq;
    using System.Threading.Tasks;
    using Identity.AuthService.Services;
    using Identity.SecurityKeyCalculation;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using Npgsql;
    using Services;

    public class UserController : Controller
    {
        private readonly IDapper _dp;
        private readonly IUserServices _userService;

        public UserController(IDapper dp, IUserServices userService)
        {
            _dp = dp;
            _userService = userService;
        }

        [HttpGet("User")]
        public async Task<string> Test()
        {
            var g = _dp.Get<string>("Select name From public.user", null, CommandType.Text);

            Console.WriteLine(g);

            return g;
        }

        [HttpPost("User/Login/{username}/PublicKey")]
        public async Task<string> LoginKey([FromRoute] string username)
        {

            var stringKey64 = _userService.GetKeyForUser(username);
            var publicstringKey = KryptTry2.GetPublicKey(stringKey64);

            return publicstringKey;
        }

        [HttpPost("User/Login/{username}")]
        public async Task<bool> Login([FromRoute] string username, [FromBody] KeyDto pass)
        {
            //var g = _dp.Get<string>("Insert Into public.user", null, CommandType.Text);
            var keyString = KeyCreation.GenerateKeys();
            KryptTry2.GetPublicKey(keyString);
            return true;
        }

        [HttpPost("User/Registration/{username}/PublicKey")]
        public async Task<string> CreateKey([FromRoute] string username)
        {
            //var g = _dp.Get<string>("Insert Into public.user", null, CommandType.Text);
            //KeyCreation.Test();


            return KryptTry2.StartHandshake();
        }


        [HttpPost("User/Registration/{username}/")]
        public async Task<bool> Registration([FromRoute] string username, [FromBody] KeyDto pass)
        {
            var privateKeyBase64 = KryptTry2.privateKeyBase64;
            _userService.RegisterUser(username, pass, privateKeyBase64);

            return true;
        }

        [HttpPost("User/Registration/{username}/test")]
        public async void AuthTest([FromRoute] string username)
        {

            KeyCreation.TestKeyAsString();

        }
    }

    public class KeyDto
    {
        public string passHash { get; set; }
    }
}
