using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;
using Microsoft.Data.Sqlite;

public class StringFormatSQLInjectionTestCases
{
    private readonly SqlCommand _command;
    private readonly SqliteCommand _sqliteCommand;
    
    public StringFormatSQLInjectionTestCases()
    {
        _command = new SqlCommand();
        _sqliteCommand = new SqliteCommand();
    }

    // ---------- True Positive (rule should trigger) ----------

    public void TP_StringFormat_WithDirectCommandText(string productName)
    {
        string query = string.Format("SELECT * FROM Products WHERE Name = '{0}'", productName);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringFormat_WithInlineUsage(string userName)
    {
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = string.Format("SELECT * FROM Users WHERE Name = '{0}'", userName);
    }

    public void TP_InterpolatedString_WithCommandText(string userId)
    {
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = $"SELECT * FROM Orders WHERE CustomerId = '{userId}'";
    }

    public void TP_StringConcat_WithCommandText(string categoryName)
    {
        string query = "SELECT * FROM Categories WHERE Name = '" + categoryName + "'";
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringConcat_MultiLine(string searchTerm)
    {
        string query = "SELECT * FROM Products WHERE " +
                      "Name LIKE '%" + searchTerm + "%'";
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringBuilder_AppendLine(string customerId)
    {
        var sb = new StringBuilder("SELECT * FROM Invoices WHERE ");
        sb.Append("CustomerId = ");
        sb.Append(customerId);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_StringBuilder_AppendFormat(string productId)
    {
        var sb = new StringBuilder();
        sb.AppendFormat("SELECT * FROM Inventory WHERE ProductId = '{0}'", productId);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_StringBuilder_ChainedAppends(string email)
    {
        var sb = new StringBuilder("SELECT * FROM Subscribers WHERE ")
            .Append("Email = '")
            .Append(email)
            .Append("'");
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_MultipleFormatMethods(string tableName, string recordId)
    {
        string query = string.Concat("SELECT * FROM ", tableName, " WHERE Id = '", recordId, "'");
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringBuilder_WithComplexLogic(string filter, int status)
    {
        var sb = new StringBuilder("SELECT * FROM Logs WHERE ");
        if (status > 0)
        {
            sb.Append("Status = ").Append(status);
        }
        if (!string.IsNullOrEmpty(filter))
        {
            sb.Append(" AND Message LIKE '%").Append(filter).Append("%'");
        }
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_StringFormat_WithMultiplePlaceholders(string firstName, string lastName)
    {
        string query = string.Format("SELECT * FROM Employees WHERE FirstName = '{0}' AND LastName = '{1}'", firstName, lastName);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringFormat_WithRepeatedUsage(string userInput)
    {
        string template = "SELECT * FROM Audit WHERE UserId = '{0}' AND Action = '{0}'";
        string query = string.Format(template, userInput);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = query;
    }

    public void TP_StringBuilder_InsertMethod(string customerName)
    {
        var sb = new StringBuilder("SELECT * FROM Customers WHERE Name = '");
        sb.Insert(sb.Length, customerName);
        sb.Append("'");
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_StringBuilder_ReplaceMethod(string oldValue, string newValue)
    {
        var sb = new StringBuilder("SELECT * FROM Settings WHERE Value = 'old'");
        sb.Replace("old", newValue);
        // ruleid: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    public void FP_StringFormat_WithSqlParameter(string productName)
    {
        string query = "SELECT * FROM Products WHERE Name = @name";
        _command.CommandText = query;
        // ok: rule-StringFormatSQLInjection
        _command.Parameters.AddWithValue("@name", productName);
    }

    public void FP_InterpolatedString_WithSqlParameter(string userName)
    {
        // ok: rule-StringFormatSQLInjection
        _command.CommandText = "SELECT * FROM Users WHERE Name = @name";
        _command.Parameters.AddWithValue("@name", userName);
    }

    public void FP_StringBuilder_WithParameterizedQuery(string customerId)
    {
        var sb = new StringBuilder("SELECT * FROM Orders WHERE CustomerId = @custId");
        // ok: rule-StringFormatSQLInjection
        _command.CommandText = sb.ToString();
        _command.Parameters.AddWithValue("@custId", customerId);
    }

    public void FP_StringFormat_WithStoredProcedure(string procedureName)
    {
        // ok: rule-StringFormatSQLInjection - хранимая процедура
        _command.CommandText = "sp_GetUserData";
        _command.CommandType = CommandType.StoredProcedure;
        _command.Parameters.AddWithValue("@userId", procedureName);
    }

    public void FP_StringConcat_WithNonSqlContext(string userInput)
    {
        // ok: rule-StringFormatSQLInjection - не SQL команда
        string logMessage = "User input: " + userInput;
        Console.WriteLine(logMessage);
    }

    public void FP_StringBuilder_WithNonSqlCommand(string userInput)
    {
        var sb = new StringBuilder("Log entry: ");
        sb.Append(userInput);
        // ok: rule-StringFormatSQLInjection
        string log = sb.ToString();
        File.WriteAllText("log.txt", log);
    }

    public void FP_StringFormat_WithEntityFrameworkCore(string productName)
    {
        // ok: rule-StringFormatSQLInjection - EF Core параметризует
        var products = _context.Products
            .FromSqlInterpolated($"SELECT * FROM Products WHERE Name = {productName}")
            .ToList();
    }

    public void FP_InterpolatedString_WithDapper(string userName)
    {
        // ok: rule-StringFormatSQLInjection - Dapper параметризует
        var users = _connection.Query<User>("SELECT * FROM Users WHERE Name = @name", 
            new { name = userName });
    }

    public void FP_StringBuilder_WithSqlKata(string tableName)
    {
        var query = new Query(tableName).Where("Id", ">", 10);
        // ok: rule-StringFormatSQLInjection - SQL построитель запросов
        string sql = query.ToString();
        _command.CommandText = sql;
    }

    public void FP_StringFormat_ForNonSqlStringFormatting(string prefix, int id)
    {
        // ok: rule-StringFormatSQLInjection - форматирование не для SQL
        string cacheKey = string.Format("user_{0}_{1}", prefix, id);
        _cache.Get(cacheKey);
    }

    public void FP_StringConcat_WithWhitelistedValue(string sortDirection)
    {
        string allowedDirections = "ASC DESC";
        if (allowedDirections.Contains(sortDirection))
        {
            string query = "SELECT * FROM Products ORDER BY Name " + sortDirection;
            // ok: rule-StringFormatSQLInjection - из whitelist
            _command.CommandText = query;
        }
    }
}