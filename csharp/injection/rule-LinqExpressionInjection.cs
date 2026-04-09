using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Linq.Dynamic.Core;
using System.Linq.Expressions;

public class LinqInjectionTestCases
{
    private readonly AppDbContext _context;

    public LinqInjectionTestCases(AppDbContext context)
    {
        _context = context;
    }

    // ---------- True Positive (rule should trigger) ----------

    public void TP_DynamicWhere_WithInterpolatedString(string userInput)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where($"Name = \"{userInput}\"").ToList();
    }

    public void TP_DynamicWhere_WithStringConcatenation(string userInput)
    {
        string filter = "Name = \"" + userInput + "\"";
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where(filter).ToList();
    }

    public void TP_DynamicWhere_WithStringVariable(string userInput)
    {
        string filter = $"Name = \"{userInput}\"";
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where(filter).ToList();
    }

    public void TP_DynamicOrderBy_WithInterpolatedString(string sortColumn, string sortDirection)
    {
        // ruleid: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy($"{sortColumn} {sortDirection}").ToList();
    }

    public void TP_DynamicOrderBy_WithStringConcatenation(string sortColumn, string sortDirection)
    {
        string orderBy = sortColumn + " " + sortDirection;
        // ruleid: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy(orderBy).ToList();
    }

    public void TP_DynamicOrderBy_WithStringVariable(string sortColumn, string sortDirection)
    {
        string orderBy = $"{sortColumn} {sortDirection}";
        // ruleid: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy(orderBy).ToList();
    }

    public void TP_DynamicWhere_WithStringFormat(string userInput)
    {
        string filter = string.Format("Name = \"{0}\"", userInput);
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where(filter).ToList();
    }

    public void TP_DynamicWhere_WithComplexExpression(string userInput, int age)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where($"Name = \"{userInput}\" AND Age = {age}").ToList();
    }

    public void TP_DynamicWhere_WithEscapeAttempt(string userInput)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Where($"Name = \"{userInput.Replace("\"", "\"\"")}\"").ToList();
    }

    public void TP_DynamicOrderBy_WithMultipleColumns(string sortColumn1, string sortColumn2, string sortDirection)
    {
        // ruleid: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy($"{sortColumn1} {sortDirection}, {sortColumn2} {sortDirection}").ToList();
    }

    public void TP_DynamicThenBy_WithInterpolatedString(string userInput)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.OrderBy(x => x.Id).ThenBy($"{userInput}").ToList();
    }

    public void TP_DynamicGroupBy_WithInterpolatedString(string groupByColumn)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.GroupBy($"{groupByColumn}").ToList();
    }

    public void TP_DynamicSelect_WithInterpolatedString(string selectColumns)
    {
        // ruleid: rule-LinqExpressionInjection
        var result = _context.Users.Select($"new({selectColumns})").ToList();
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    public void FP_DynamicWhere_WithParameterizedFilter(string userInput)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Name = @0", userInput).ToList();
    }

    public void FP_DynamicWhere_WithMultipleParameters(string name, int age)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Name = @0 AND Age = @1", name, age).ToList();
    }

    public void FP_DynamicWhere_WithParameterArray(string userInput)
    {
        object[] parameters = { userInput };
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Name = @0", parameters).ToList();
    }

    public void FP_DynamicOrderBy_WithConstantString()
    {
        // ok: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy("Name ASC").ToList();
    }

    public void FP_DynamicOrderBy_WithWhitelistedColumns(string sortDirection)
    {
        string sortColumn = "Name"; // Из безопасного whitelist'а
        string orderBy = $"{sortColumn} {sortDirection}";
        // ok: rule-LinqExpressionInjection - column из whitelist
        var sorted = _context.Users.OrderBy(orderBy).ToList();
    }

    public void FP_StaticLinq_WithExpressionLambda(string userInput)
    {
        // ok: rule-LinqExpressionInjection - статический LINQ, не Dynamic LINQ
        var result = _context.Users.Where(u => u.Name == userInput).ToList();
    }

    public void FP_StaticLinq_WithOrderByLambda(string sortDirection)
    {
        // ok: rule-LinqExpressionInjection
        var sorted = _context.Users.OrderBy(u => u.Name).ToList();
    }

    public void FP_DynamicWhere_WithSafePropertyAccess(string userInput)
    {
        // ok: rule-LinqExpressionInjection - использование It вместо строки
        var result = _context.Users.Where("Name == @0", userInput).ToList();
    }

    public void FP_DynamicWhere_WithEnumValue(int userStatus)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Status = @0", userStatus).ToList();
    }

    public void FP_DynamicWhere_WithGuidParameter(Guid userId)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Id = @0", userId).ToList();
    }

    public void FP_DynamicWhere_WithDateTimeParameter(DateTime registrationDate)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("RegistrationDate > @0", registrationDate).ToList();
    }

    public void FP_EntityFramework_CompiledQuery(string userInput)
    {
        // ok: rule-LinqExpressionInjection - обычный EF запрос
        var query = _context.Users.Where(u => u.Name == userInput);
        var result = query.ToList();
    }

    public void FP_DynamicWhere_WithStringComparisonAndParameter(string userInput)
    {
        // ok: rule-LinqExpressionInjection
        var result = _context.Users.Where("Name.ToLower() == @0", userInput.ToLower()).ToList();
    }

    public void FP_FromSqlInterpolated_WithFormattableString(string userInput)
    {
        // ok: rule-LinqExpressionInjection - это SQL инъекция, не LINQ инъекция
        var result = _context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userInput}").ToList();
    }
}