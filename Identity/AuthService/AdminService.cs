﻿using System;
using System.Threading.Tasks;
using FrontEnd.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServices
{
    public class AdminService : IAdminService
    {
        private readonly IServiceProvider _serviceProvider;

        private bool _adminExists;

        public AdminService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task<bool> AllowAdminUserCreationAsync()
        {
            if (_adminExists)
            {
                return false;
            }
            else
            {
                using var scope = _serviceProvider.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();

                if (!await dbContext.Users.AnyAsync(user => user.IsAdmin)) return true;
                // There are already admin users so disable admin creation
                _adminExists = true;
                return false;
            }
        }
    }
}