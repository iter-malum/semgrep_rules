using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Dapper;
using Microsoft.EntityFrameworkCore;
using NHibernate;

public class ORMWriteConcatenationTestCases
{
    private readonly AppDbContext _context;
    private readonly IDbConnection _connection;
    private readonly ISession _nhSession;

    public ORMWriteConcatenationTestCases(AppDbContext context, IDbConnection connection, ISession nhSession)
    {
        _context = context;
        _connection = connection;
        _nhSession = nhSession;
    }

    // ---------- True Positive (rule should trigger) ----------

    // EF Core - ExecuteSqlRaw
    public void TP_EFCore_ExecuteSqlRaw_WithInterpolation(string status, int userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw($"UPDATE Users SET Status = '{status}' WHERE Id = {userId}");
    }

    public void TP_EFCore_ExecuteSqlRaw_WithConcatenation(string status, int userId)
    {
        string sql = "UPDATE Users SET Status = '" + status + "' WHERE Id = " + userId;
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sql);
    }

    public void TP_EFCore_ExecuteSqlRaw_WithStringFormat(string status, int userId)
    {
        string sql = string.Format("UPDATE Users SET Status = '{0}' WHERE Id = {1}", status, userId);
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sql);
    }

    public void TP_EFCore_ExecuteSqlRaw_WithStringBuilder(string status, int userId)
    {
        var sb = new StringBuilder("UPDATE Users SET Status = '");
        sb.Append(status);
        sb.Append("' WHERE Id = ");
        sb.Append(userId);
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sb.ToString());
    }

    // EF Core - ExecuteSqlRaw with async
    public async Task TP_EFCore_ExecuteSqlRawAsync_WithInterpolation(string status, int userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        await _context.Database.ExecuteSqlRawAsync($"UPDATE Users SET Status = '{status}' WHERE Id = {userId}");
    }

    // EF Core - ExecuteSqlInterpolated (when misused)
    public void TP_EFCore_ExecuteSqlInterpolated_WithStringVariable(string status, int userId)
    {
        string sql = $"UPDATE Users SET Status = '{status}' WHERE Id = {userId}";
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlInterpolated(sql);
    }

    public void TP_EFCore_ExecuteSqlInterpolated_WithStringCast(string status, int userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlInterpolated((string)$"UPDATE Users SET Status = '{status}' WHERE Id = {userId}");
    }

    // EF Core - ExecuteSqlRaw for DELETE
    public void TP_EFCore_ExecuteSqlRaw_DeleteWithInterpolation(string cutoffDate)
    {
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw($"DELETE FROM Logs WHERE Date < '{cutoffDate}'");
    }

    // EF Core - ExecuteSqlRaw for INSERT
    public void TP_EFCore_ExecuteSqlRaw_InsertWithConcatenation(string tableName, string name, string value)
    {
        string sql = "INSERT INTO " + tableName + " (Name, Value) VALUES ('" + name + "', '" + value + "')";
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sql);
    }

    // Dapper - Execute
    public void TP_Dapper_Execute_WithInterpolation(string cutoffDate)
    {
        // ruleid: rule-ORMWriteConcatenation
        _connection.Execute($"DELETE FROM Logs WHERE Date < '{cutoffDate}'");
    }

    public void TP_Dapper_Execute_WithConcatenation(string status, int userId)
    {
        string sql = "UPDATE Users SET Status = '" + status + "' WHERE Id = " + userId;
        // ruleid: rule-ORMWriteConcatenation
        _connection.Execute(sql);
    }

    public void TP_Dapper_Execute_WithStringFormat(string status, int userId)
    {
        string sql = string.Format("UPDATE Users SET Status = '{0}' WHERE Id = {1}", status, userId);
        // ruleid: rule-ORMWriteConcatenation
        _connection.Execute(sql);
    }

    public void TP_Dapper_Execute_WithStringBuilder(string status, int userId)
    {
        var sb = new StringBuilder("UPDATE Users SET Status = '");
        sb.Append(status);
        sb.Append("' WHERE Id = ");
        sb.Append(userId);
        // ruleid: rule-ORMWriteConcatenation
        _connection.Execute(sb.ToString());
    }

    // Dapper - ExecuteAsync
    public async Task TP_Dapper_ExecuteAsync_WithInterpolation(string cutoffDate)
    {
        // ruleid: rule-ORMWriteConcatenation
        await _connection.ExecuteAsync($"DELETE FROM Logs WHERE Date < '{cutoffDate}'");
    }

    // Dapper - Query (non-select operations can be dangerous too)
    public void TP_Dapper_Query_WithInterpolation(string status, int userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        var result = _connection.Query($"UPDATE Users SET Status = '{status}' WHERE Id = {userId}; SELECT @@ROWCOUNT");
    }

    // Dapper - ExecuteScalar
    public void TP_Dapper_ExecuteScalar_WithInterpolation(string email, string userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        var count = _connection.ExecuteScalar<int>($"UPDATE Users SET Email = '{email}' WHERE Id = {userId}; SELECT @@ROWCOUNT");
    }

    // Dapper - ExecuteReader
    public void TP_Dapper_ExecuteReader_WithInterpolation(string productName, int productId)
    {
        // ruleid: rule-ORMWriteConcatenation
        var reader = _connection.ExecuteReader($"UPDATE Products SET Name = '{productName}' WHERE Id = {productId}");
    }

    // NHibernate - CreateSQLQuery (modification)
    public void TP_NHibernate_CreateSQLQuery_WithInterpolation(string status, int userId)
    {
        // ruleid: rule-ORMWriteConcatenation
        _nhSession.CreateSQLQuery($"UPDATE Users SET Status = '{status}' WHERE Id = {userId}").ExecuteUpdate();
    }

    public void TP_NHibernate_CreateSQLQuery_WithConcatenation(string status, int userId)
    {
        string sql = "UPDATE Users SET Status = '" + status + "' WHERE Id = " + userId;
        // ruleid: rule-ORMWriteConcatenation
        _nhSession.CreateSQLQuery(sql).ExecuteUpdate();
    }

    // NHibernate - CreateSQLQuery for DELETE
    public void TP_NHibernate_CreateSQLQuery_DeleteWithInterpolation(string cutoffDate)
    {
        // ruleid: rule-ORMWriteConcatenation
        _nhSession.CreateSQLQuery($"DELETE FROM Logs WHERE Date < '{cutoffDate}'").ExecuteUpdate();
    }

    // Multiple operations in one call
    public void TP_EFCore_ExecuteSqlRaw_MultipleStatements(string tableName, string value)
    {
        string sql = $"INSERT INTO {tableName} (Value) VALUES ('{value}'); UPDATE Audit SET Count = Count + 1";
        // ruleid: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sql);
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // EF Core - ExecuteSqlRaw with parameters
    public void FP_EFCore_ExecuteSqlRaw_WithParameters(string status, int userId)
    {
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw("UPDATE Users SET Status = @status WHERE Id = @userId", 
            new SqlParameter("@status", status), 
            new SqlParameter("@userId", userId));
    }

    // EF Core - ExecuteSqlInterpolated with FormattableString (safe)
    public void FP_EFCore_ExecuteSqlInterpolated_WithFormattableString(string status, int userId)
    {
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlInterpolated($"UPDATE Users SET Status = {status} WHERE Id = {userId}");
    }

    // EF Core - ExecuteSqlInterpolated with FormattableString variable (safe)
    public void FP_EFCore_ExecuteSqlInterpolated_WithFormattableStringVariable(string status, int userId)
    {
        FormattableString fs = $"UPDATE Users SET Status = {status} WHERE Id = {userId}";
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlInterpolated(fs);
    }

    // Dapper - Execute with parameters (safe)
    public void FP_Dapper_Execute_WithParameters(string status, int userId)
    {
        // ok: rule-ORMWriteConcatenation
        _connection.Execute("UPDATE Users SET Status = @status WHERE Id = @userId", 
            new { status, userId });
    }

    // Dapper - Execute with DynamicParameters
    public void FP_Dapper_Execute_WithDynamicParameters(string status, int userId)
    {
        var parameters = new DynamicParameters();
        parameters.Add("@status", status);
        parameters.Add("@userId", userId);
        // ok: rule-ORMWriteConcatenation
        _connection.Execute("UPDATE Users SET Status = @status WHERE Id = @userId", parameters);
    }

    // Dapper - ExecuteAsync with parameters
    public async Task FP_Dapper_ExecuteAsync_WithParameters(string cutoffDate)
    {
        // ok: rule-ORMWriteConcatenation
        await _connection.ExecuteAsync("DELETE FROM Logs WHERE Date < @cutoffDate", 
            new { cutoffDate });
    }

    // Dapper - Query with parameters (safe)
    public void FP_Dapper_Query_WithParameters(string status, int userId)
    {
        // ok: rule-ORMWriteConcatenation
        var result = _connection.Query("SELECT * FROM Users WHERE Status = @status AND Id = @userId", 
            new { status, userId });
    }

    // NHibernate - CreateSQLQuery with parameter (safe)
    public void FP_NHibernate_CreateSQLQuery_WithParameter(string status, int userId)
    {
        // ok: rule-ORMWriteConcatenation
        _nhSession.CreateSQLQuery("UPDATE Users SET Status = :status WHERE Id = :userId")
            .SetParameter("status", status)
            .SetParameter("userId", userId)
            .ExecuteUpdate();
    }

    // NHibernate - CreateSQLQuery for SELECT (not modification)
    public void FP_NHibernate_CreateSQLQuery_SelectWithInterpolation(string userName)
    {
        // ok: rule-ORMWriteConcatenation - SELECT, не модификация
        var users = _nhSession.CreateSQLQuery($"SELECT * FROM Users WHERE Name = '{userName}'").List();
    }

    // EF Core - ExecuteSqlRaw with constant string
    public void FP_EFCore_ExecuteSqlRaw_WithConstant()
    {
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw("UPDATE Users SET LastLogin = GETDATE() WHERE Id = 1");
    }

    // EF Core - ExecuteSqlInterpolated with constant values
    public void FP_EFCore_ExecuteSqlInterpolated_WithConstants()
    {
        int status = 1;
        int userId = 100;
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlInterpolated($"UPDATE Users SET Status = {status} WHERE Id = {userId}");
    }

    // Dapper - Execute with stored procedure
    public void FP_Dapper_Execute_WithStoredProcedure(string userId)
    {
        // ok: rule-ORMWriteConcatenation
        _connection.Execute("usp_UpdateUser", new { userId }, commandType: CommandType.StoredProcedure);
    }

    // EF Core - ExecuteSqlRaw with FromSql pattern (query, not modification)
    public void FP_EFCore_FromSqlRaw_WithInterpolation(string userName)
    {
        // ok: rule-ORMWriteConcatenation - это SELECT, не модификация данных
        var users = _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{userName}'").ToList();
    }

    // Regular ADO.NET with parameters (covered by other rules)
    public void FP_AdoNet_WithParameters(string status, int userId)
    {
        using var cmd = new SqlCommand("UPDATE Users SET Status = @status WHERE Id = @userId");
        cmd.Parameters.AddWithValue("@status", status);
        cmd.Parameters.AddWithValue("@userId", userId);
        // ok: rule-ORMWriteConcatenation
        cmd.ExecuteNonQuery();
    }

    // StringBuilder but with parameters
    public void FP_StringBuilder_WithParameterizedQuery(string status, int userId)
    {
        var sb = new StringBuilder("UPDATE Users SET Status = @status WHERE Id = @userId");
        // ok: rule-ORMWriteConcatenation
        _context.Database.ExecuteSqlRaw(sb.ToString(), 
            new SqlParameter("@status", status),
            new SqlParameter("@userId", userId));
    }
}

// Missing context class
public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
}

public class User { }