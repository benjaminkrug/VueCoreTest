INSERT INTO "AspNetUsers" ("Id", "UserName", "NormalizedUserName", "Email", "NormalizedEmail", "EmailConfirmed", "PasswordHash", "SecurityStamp", "ConcurrencyStamp", "PhoneNumber", "PhoneNumberConfirmed", "TwoFactorEnabled", "LockoutEnd", "LockoutEnabled", "AccessFailedCount", "IsAdmin")
VALUES (gen_random_uuid(),
        @username,
        UPPER(@username),
        @email,
        UPPER(@email),
        FALSE,
        @pass,
        @salt,
        NULL,
        '',
        FALSE,
        FALSE,
        NULL,
        FALSE,
        0,
        @isadmin)
ON CONFLICT DO NOTHING;