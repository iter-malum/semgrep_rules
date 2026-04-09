using Microsoft.EntityFrameworkCore;
using System;
using System.Data.SqlClient;

public class TestCases
{
    private readonly AppDbContext _context;

    public TestCases(AppDbContext context)
    {
        _context = context;
    }

    // ---------- True Positive (rule should trigger) ----------

    public void TP_FromSqlRaw_WithInterpolatedString(string userInput)
    {
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{userInput}'").ToList();
    }

    public void TP_FromSqlRaw_WithStringVariable(string userInput)
    {
        string sql = $"SELECT * FROM Users WHERE Name = '{userInput}'";
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql).ToList();
    }

    public void TP_FromSqlInterpolated_WithStringVariable(string tableName, string userInput)
    {
        string sql = $"SELECT * FROM {tableName} WHERE Name = '{userInput}'";
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var data = _context.Entities.FromSqlInterpolated(sql).ToList();
    }

    public void TP_FromSqlInterpolated_WithStringCast(string userInput)
    {
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated((string)$"SELECT * FROM Users WHERE Name = '{userInput}'").ToList();
    }

    public void TP_FromSqlRaw_WithStringBuilder(string userInput)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("SELECT * FROM Users WHERE Name = '");
        sb.Append(userInput);
        sb.Append("'");
        string sql = sb.ToString();
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql).ToList();
    }

    public void TP_FromSqlInterpolated_WithStringConcatenation(string userInput)
    {
        string sql = "SELECT * FROM Users WHERE Name = '" + userInput + "'";
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated(sql).ToList();
    }

    public void TP_FromSqlRaw_WithFormattedString(string userInput)
    {
        string sql = string.Format("SELECT * FROM Users WHERE Name = '{0}'", userInput);
        // ruleid: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql).ToList();
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    public void FP_FromSqlInterpolated_WithDirectInterpolatedString(string userInput)
    {
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userInput}").ToList();
    }

    public void FP_FromSqlInterpolated_WithMultipleParameters(int id, string name)
    {
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id} AND Name = {name}").ToList();
    }

    public void FP_FromSqlRaw_WithSqlParameter(string userInput)
    {
        var sql = "SELECT * FROM Users WHERE Name = @name";
        var param = new SqlParameter("@name", userInput);
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql, param).ToList();
    }

    public void FP_FromSqlRaw_WithSqlParameterArray(string userInput)
    {
        var sql = "SELECT * FROM Users WHERE Name = @name";
        var parameters = new[] { new SqlParameter("@name", userInput) };
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql, parameters).ToList();
    }

    public void FP_ExecuteSqlInterpolated_WithDirectInterpolatedString(string userInput)
    {
        // ok: rule-EFCoreInterpolatedStringInjection
        _context.Database.ExecuteSqlInterpolated($"UPDATE Users SET Name = {userInput} WHERE Id = 1");
    }

    public void FP_FormattableStringVariable(string userInput)
    {
        FormattableString fs = $"SELECT * FROM Users WHERE Name = {userInput}";
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated(fs).ToList();
    }

    public void FP_FromSqlRaw_WithConstantString()
    {
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw("SELECT * FROM Users WHERE Active = 1").ToList();
    }

    public void FP_FromSqlInterpolated_WithConstantInterpolatedString()
    {
        int activeStatus = 1;
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Active = {activeStatus}").ToList();
    }

    public void FP_ExecuteSqlRaw_WithSqlParameter(string userInput)
    {
        var sql = "UPDATE Users SET Name = @name WHERE Id = 1";
        var param = new SqlParameter("@name", userInput);
        // ok: rule-EFCoreInterpolatedStringInjection
        _context.Database.ExecuteSqlRaw(sql, param);
    }

    public void FP_FromSqlRaw_WithFormattableStringCast(string userInput)
    {
        FormattableString fs = $"SELECT * FROM Users WHERE Name = {userInput}";
        string sql = fs.ToString();
        // ok: rule-EFCoreInterpolatedStringInjection
        var users = _context.Users.FromSqlRaw(sql).ToList();
    }
}