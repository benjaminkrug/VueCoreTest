using Dapper;  
using Microsoft.Extensions.Configuration;  
using System;  
using System.Collections.Generic;  
using System.Data;  
using System.Data.Common;  
using System.Data.SqlClient;  
using System.Linq;  
using Npgsql;
using System.IO;

namespace Services
{
    public class DapperrAuth: IDapperAuth
    {
        
        private readonly IConfiguration _config;  
        private string Connectionstring = "DefaultAuthConnection";

        // insert enviroment Prop here for D:path...
        private string query = @"D:\privateWork\repo\Königsleiten 2\VueCoreTest\VueCoreTest\Identity\AuthService\Services\sql\";
        private string _sql = ".sql";

        public DapperrAuth(IConfiguration config)  
        {  
            _config = config;  
        }  
        public void Dispose()  
        {  
             
        }  
  
        public int Execute(string sp, DynamicParameters parms, CommandType commandType = CommandType.StoredProcedure)  
        {  
            throw new NotImplementedException();  
        }  
  
        public T Get<T>(string sp, DynamicParameters parms, CommandType commandType = CommandType.Text)  
        {  
            using IDbConnection db = new NpgsqlConnection(_config.GetConnectionString(Connectionstring));  
            return db.Query<T>(GetFileQueryIfPossible(sp), parms, commandType: commandType).FirstOrDefault();  
        }  
  
        public List<T> GetAll<T>(string sp, DynamicParameters parms, CommandType commandType = CommandType.StoredProcedure)  
        {  
            using IDbConnection db = new NpgsqlConnection(_config.GetConnectionString(Connectionstring));  
            return db.Query<T>(GetFileQueryIfPossible(sp), parms, commandType: commandType).ToList();  
        }  
  
        public DbConnection GetDbconnection()  
        {  
            return new NpgsqlConnection(_config.GetConnectionString(Connectionstring));  
        }  
  
        public T Insert<T>(string sp, DynamicParameters parms, CommandType commandType = CommandType.StoredProcedure)  
        {  
            T result;  
            using IDbConnection db = new NpgsqlConnection(_config.GetConnectionString(Connectionstring));  
            try  
            {  
                if (db.State == ConnectionState.Closed)  
                    db.Open();  
  
                using var tran = db.BeginTransaction();  
                try  
                {  
                    result = db.Query<T>(GetFileQueryIfPossible(sp), parms, commandType: commandType, transaction: tran).FirstOrDefault();  
                    tran.Commit();  
                }  
                catch (Exception ex)  
                {  
                    tran.Rollback();  
                    throw ex;  
                }  
            }  
            catch (Exception ex)  
            {  
                throw ex;  
            }  
            finally  
            {  
                if (db.State == ConnectionState.Open)  
                    db.Close();  
            }  
  
            return result;  
        }  
  
        public T Update<T>(string sp, DynamicParameters parms, CommandType commandType = CommandType.StoredProcedure)  
        {  
            T result;  
            using IDbConnection db = new NpgsqlConnection(_config.GetConnectionString(Connectionstring));  
            try  
            {  
                if (db.State == ConnectionState.Closed)  
                    db.Open();  
  
                using var tran = db.BeginTransaction();  
                try  
                {  
                    result = db.Query<T>(GetFileQueryIfPossible(sp), parms, commandType: commandType, transaction: tran).FirstOrDefault();  
                    tran.Commit();  
                }  
                catch (Exception ex)  
                {  
                    tran.Rollback();  
                    throw ex;  
                }  
            }  
            catch (Exception ex)  
            {  
                throw ex;  
            }  
            finally  
            {  
                if (db.State == ConnectionState.Open)  
                    db.Close();  
            }  
  
            return result;
        }
        private string CombinePath(string path)
        {
            var newPath = string.Concat(query, path);
            if (!newPath.EndsWith(".sql"))
            {
                newPath = string.Concat(newPath, _sql);
            }

            return newPath;
        }
        private string GetFileQueryIfPossible(string sp)
        {
            return File.ReadAllText(CombinePath(sp));
        }
    }
}