using System;
using System.Data;
using System.Data.SqlClient;
using System.Text;

public class StoredProcedureParameterInjectionTestCases
{
    private readonly SqlCommand _command;
    private readonly SqlConnection _connection;

    public StoredProcedureParameterInjectionTestCases()
    {
        _command = new SqlCommand();
        _connection = new SqlConnection();
        _command.Connection = _connection;
    }

    // ---------- True Positive (rule should trigger) ----------

    public void TP_DynamicProcedureName_WithInterpolation(string entityType, string userId)
    {
        string procName = $"usp_Get{entityType}Data";
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
    }

    public void TP_DynamicProcedureName_WithConcatenation(string entityType)
    {
        string procName = "usp_Get" + entityType + "Data";
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
    }

    public void TP_DynamicProcedureName_WithStringFormat(string entityType)
    {
        string procName = string.Format("usp_Get{0}Data", entityType);
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
    }

    public void TP_DynamicProcedureName_WithStringBuilder(string entityType)
    {
        var sb = new StringBuilder("usp_Get");
        sb.Append(entityType);
        sb.Append("Data");
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_ExecuteSql_WithDynamicExec(string userName)
    {
        string execSql = $"EXECUTE sp_GetUser '{userName}'";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_ExecuteSql_WithConcatenation(string userName)
    {
        string execSql = "EXECUTE sp_GetUser '" + userName + "'";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_ExecuteSql_WithStringFormat(string userName)
    {
        string execSql = string.Format("EXECUTE sp_GetUser '{0}'", userName);
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_Exec_WithoutExecute(string roleName)
    {
        string execSql = $"EXEC sp_GetUsersByRole '{roleName}'";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_MultipleDynamicProcedures(string module, string action)
    {
        string procName = $"usp_{module}_{action}";
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
    }

    public void TP_DynamicProcedureWithParameters(string reportType, string date)
    {
        string procName = $"usp_Generate{reportType}Report";
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
        _command.Parameters.AddWithValue("@date", date);
    }

    public void TP_ExecuteSql_WithMultipleStatements(string tableName, string userId)
    {
        string execSql = $"EXECUTE sp_TransferData '{tableName}', '{userId}'";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_Exec_WithVariableAssignment(string schemaName)
    {
        string execSql = $"DECLARE @procName NVARCHAR(100) = 'usp_Get{schemaName}Data'; EXEC @procName";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    public void TP_ExecuteSql_WithStringBuilder(string filter)
    {
        var sb = new StringBuilder("EXECUTE sp_SearchData '");
        sb.Append(filter);
        sb.Append("'");
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = sb.ToString();
    }

    public void TP_StoredProcedure_WithDynamicSchema(string schemaName, string procedureName)
    {
        string fullProcName = $"[{schemaName}].[{procedureName}]";
        _command.CommandType = CommandType.StoredProcedure;
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = fullProcName;
    }

    public void TP_ExecuteSql_WithQuotedIdentifier(string userInput)
    {
        string execSql = $"EXECUTE sp_GetData @param = '{userInput}'";
        // ruleid: rule-StoredProcedureParameterInjection
        _command.CommandText = execSql;
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    public void FP_StoredProcedure_WithConstantName()
    {
        _command.CommandType = CommandType.StoredProcedure;
        // ok: rule-StoredProcedureParameterInjection
        _command.CommandText = "usp_GetUserData";
        _command.Parameters.AddWithValue("@userId", 123);
    }

    public void FP_StoredProcedure_WithConstVariable()
    {
        const string procName = "usp_GetProducts";
        _command.CommandType = CommandType.StoredProcedure;
        // ok: rule-StoredProcedureParameterInjection
        _command.CommandText = procName;
    }

    public void FP_StoredProcedure_WithWhitelistedValue(string operationType)
    {
        string[] allowedProcs = { "usp_Create", "usp_Update", "usp_Delete" };
        if (Array.IndexOf(allowedProcs, operationType) >= 0)
        {
            _command.CommandType = CommandType.StoredProcedure;
            // ok: rule-StoredProcedureParameterInjection - из whitelist
            _command.CommandText = operationType;
        }
    }

    public void FP_StoredProcedure_WithEnumValue(ReportType reportType)
    {
        string procName = reportType == ReportType.Summary ? "usp_GetSummary" : "usp_GetDetails";
        _command.CommandType = CommandType.StoredProcedure;
        // ok: rule-StoredProcedureParameterInjection - из enum
        _command.CommandText = procName;
    }

    public void FP_ParameterizedQuery_WithCommandText()
    {
        // ok: rule-StoredProcedureParameterInjection - обычный SQL, не хранимая процедура
        _command.CommandText = "SELECT * FROM Users WHERE Name = @name";
        _command.Parameters.AddWithValue("@name", "John");
    }

    public void FP_ExecuteSql_WithParameters(string userName)
    {
        // ok: rule-StoredProcedureParameterInjection - параметризованный EXECUTE
        _command.CommandText = "EXECUTE sp_GetUser @userName";
        _command.Parameters.AddWithValue("@userName", userName);
    }

    public void FP_ExecuteSql_WithSqlParameterArray(string userId)
    {
        string execSql = "EXECUTE sp_GetOrders @customerId";
        _command.CommandText = execSql;
        // ok: rule-StoredProcedureParameterInjection
        _command.Parameters.AddWithValue("@customerId", userId);
    }

    public void FP_StoredProcedure_WithSwitchStatement(string action)
    {
        string procName;
        switch (action.ToLower())
        {
            case "user":
                procName = "usp_GetUserData";
                break;
            case "product":
                procName = "usp_GetProductData";
                break;
            default:
                procName = "usp_GetDefaultData";
                break;
        }
        _command.CommandType = CommandType.StoredProcedure;
        // ok: rule-StoredProcedureParameterInjection - из switch
        _command.CommandText = procName;
    }

    public void FP_StoredProcedure_WithDictionaryLookup(string entityType)
    {
        var procMap = new Dictionary<string, string>
        {
            ["user"] = "usp_GetUserData",
            ["product"] = "usp_GetProductData",
            ["order"] = "usp_GetOrderData"
        };
        
        if (procMap.TryGetValue(entityType, out string procName))
        {
            _command.CommandType = CommandType.StoredProcedure;
            // ok: rule-StoredProcedureParameterInjection - из словаря
            _command.CommandText = procName;
        }
    }

    public void FP_EntityFramework_StoredProcedure(string userId)
    {
        // ok: rule-StoredProcedureParameterInjection - EF Core параметризует
        var users = _context.Users
            .FromSqlInterpolated($"EXECUTE usp_GetUserData @userId = {userId}")
            .ToList();
    }

    public void FP_Dapper_StoredProcedure(string userId)
    {
        // ok: rule-StoredProcedureParameterInjection - Dapper с параметрами
        var user = _connection.QueryFirstOrDefault<User>(
            "usp_GetUserData", 
            new { userId }, 
            commandType: CommandType.StoredProcedure);
    }

    public void FP_StoredProcedure_WithStringBuilderConstant(string entityType)
    {
        var sb = new StringBuilder("usp_Get");
        sb.Append("User"); // Константа, не пользовательский ввод
        sb.Append("Data");
        _command.CommandType = CommandType.StoredProcedure;
        // ok: rule-StoredProcedureParameterInjection
        _command.CommandText = sb.ToString();
    }
}

public enum ReportType
{
    Summary,
    Details,
    Analytics
}

public class User { }