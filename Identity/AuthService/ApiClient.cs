using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace FrontEnd.Services
{
    public class ApiClient: IApiClient
    {
        private readonly HttpClient _httpClient;

        public ApiClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }
        
        public async Task<string> GetUsersAsync()
        {
            var response = await _httpClient.GetStringAsync($"/User");  
            
            return response;
        }

        public async Task<string> GetBackendTest()
        {
            var response = await _httpClient.GetStringAsync($"/Test");  
            var Text = response.ToString();
            Console.WriteLine( Text);
            return Text;
        }
    }
}