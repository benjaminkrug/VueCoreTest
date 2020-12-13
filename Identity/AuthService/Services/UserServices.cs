using Dapper;
using Services;
using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Webapp.Controllers;

namespace Identity.AuthService.Services
{
    public class UserServices : IUserServices
    {
        private readonly IDapperAuth _dp;

        public UserServices(IDapperAuth dp)
        {
            _dp = dp;
        }

        public bool RegisterUser(string username, KeyDto pass, string privateKeyBase64)
        {
            //DynamicParameters obj = new DynamicParameters();
            //obj.Add("@username", username);
            //obj.Add("@email", "");
            //obj.Add("@pass", pass.passHash);
            //obj.Add("@salt", privateKeyBase64);
            //obj.Add("@isAdmin", true);
            object obj = new { username, email= "", pass = pass.passHash, salt = privateKeyBase64, isAdmin = true };

            var g = _dp.Get<bool>("CreateNewUser", new DynamicParameters(obj), CommandType.Text);
            //Von der Auswertung der Methode "Services.DapperrAuth.Insert(string, Dapper.DynamicParameters, System.Data.CommandType)" wird ein Aufruf in der nativen Methode "System.DateTime.GetSystemTimeWithLeapSecondsHandling(System.DateTime+FullSystemTime*)" ausgeführt. Das Auswerten nativer Methoden in diesem Kontext wird nicht unterstützt.

            return true;
        }

        public string GetKeyForUser(string username)
        {
           var key = _dp.Get<string>("GetStampForUser", new DynamicParameters(new {username }), CommandType.Text);

            return key;
        }
    }
}
