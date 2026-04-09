using System;
using System.Text;
using Microsoft.Extensions.Logging;
using Serilog;
using NLog;
using log4net;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace LogInjectionTestCases
{
    public class LogInjectionController : Controller
    {
        private readonly ILogger<LogInjectionController> _logger;
        private readonly Serilog.ILogger _serilog;
        private readonly NLog.ILogger _nlogger;
        private readonly log4net.ILog _log4net;
        
        public LogInjectionController(
            ILogger<LogInjectionController> logger,
            Serilog.ILogger serilog,
            NLog.ILogger nlogger,
            log4net.ILog log4net)
        {
            _logger = logger;
            _serilog = serilog;
            _nlogger = nlogger;
            _log4net = log4net;
        }

        // ---------- True Positive (rule should trigger) ----------

        // TP1: Прямая запись user input в лог (ILogger)
        public IActionResult TP1_LoggerLogInformation(string username)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User {username} logged in");
            return Ok();
        }

        // TP2: Интерполяция строк в лог
        public IActionResult TP2_InterpolatedString(string searchTerm)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogError($"Search failed for term: {searchTerm}");
            return BadRequest();
        }

        // TP3: Конкатенация строк в лог
        public IActionResult TP3_StringConcat(string fileName)
        {
            string logMessage = "File uploaded: " + fileName;
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation(logMessage);
            return Ok();
        }

        // TP4: String.Format в лог
        public IActionResult TP4_StringFormat(string userId, string action)
        {
            string logMsg = string.Format("User {0} performed {1}", userId, action);
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogWarning(logMsg);
            return Ok();
        }

        // TP5: StringBuilder для лога
        public IActionResult TP5_StringBuilder(string input)
        {
            var sb = new StringBuilder();
            sb.Append("User input: ");
            sb.Append(input);
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogDebug(sb.ToString());
            return Ok();
        }

        // TP6: Serilog с user input
        public IActionResult TP6_SerilogInformation(string apiKey)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _serilog.Information($"API key used: {apiKey}");
            return Ok();
        }

        // TP7: Serilog Error с user input
        public IActionResult TP7_SerilogError(string exceptionDetails)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _serilog.Error($"Exception occurred: {exceptionDetails}");
            return StatusCode(500);
        }

        // TP8: NLog с user input
        public IActionResult TP8_NLogInfo(string message)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _nlogger.Info($"User message: {message}");
            return Ok();
        }

        // TP9: NLog Warn с user input
        public IActionResult TP9_NLogWarn(string suspiciousActivity)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _nlogger.Warn($"Suspicious: {suspiciousActivity}");
            return Ok();
        }

        // TP10: log4net с user input
        public IActionResult TP10_Log4NetInfo(string userData)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _log4net.Info($"User data: {userData}");
            return Ok();
        }

        // TP11: log4net Error с user input
        public IActionResult TP11_Log4NetError(string errorContext)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _log4net.Error($"Error context: {errorContext}");
            return Ok();
        }

        // TP12: Console.WriteLine с user input
        public IActionResult TP12_ConsoleWrite(string input)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            Console.WriteLine($"User input: {input}");
            return Ok();
        }

        // TP13: Debug.WriteLine с user input
        public IActionResult TP13_DebugWrite(string debugInfo)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            System.Diagnostics.Debug.WriteLine($"Debug: {debugInfo}");
            return Ok();
        }

        // TP14: Trace.WriteLine с user input
        public IActionResult TP14_TraceWrite(string traceData)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            System.Diagnostics.Trace.WriteLine($"Trace: {traceData}");
            return Ok();
        }

        // TP15: EventLog.WriteEntry
        public IActionResult TP15_EventLogWrite(string applicationEvent)
        {
            using (var eventLog = new System.Diagnostics.EventLog("Application"))
            {
                // ruleid: csharp_log_injection_Rule-LogInjection
                eventLog.WriteEntry($"Event: {applicationEvent}");
            }
            return Ok();
        }

        // TP16: HttpContext.Trace.Write
        public IActionResult TP16_HttpContextTrace(string traceMessage)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            HttpContext.Trace.Write($"Trace: {traceMessage}");
            return Ok();
        }

        // TP17: Log с CRLF injection
        public IActionResult TP17_CRLFInjection(string userInput)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User input: {userInput}");
            return Ok();
        }

        // TP18: Log с NewLine characters
        public IActionResult TP18_NewLineInjection(string multilineInput)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogWarning($"Multiline: {multilineInput}");
            return Ok();
        }

        // TP19: User input из Query параметра
        public IActionResult TP19_FromQueryParam([FromQuery] string q)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Search query: {q}");
            return Ok();
        }

        // TP20: User input из тела запроса
        [HttpPost]
        public IActionResult TP20_FromBody([FromBody] LoginRequest request)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Login attempt for: {request.Username}");
            return Ok();
        }

        // TP21: User input из Route
        [HttpGet("user/{id}/activity")]
        public IActionResult TP21_FromRoute(string id)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User activity for ID: {id}");
            return Ok();
        }

        // TP22: User input из заголовка
        public IActionResult TP22_FromHeader([FromHeader] string userAgent)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User-Agent: {userAgent}");
            return Ok();
        }

        // TP23: User input из Cookie
        public IActionResult TP23_FromCookie(string sessionId)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Session ID: {sessionId}");
            return Ok();
        }

        // TP24: Base64 encoded user input
        public IActionResult TP24_Base64Input(string encodedData)
        {
            byte[] data = Convert.FromBase64String(encodedData);
            string decoded = Encoding.UTF8.GetString(data);
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Decoded: {decoded}");
            return Ok();
        }

        // TP25: UrlDecoded user input
        public IActionResult TP25_UrlDecodedInput(string encoded)
        {
            string decoded = Uri.UnescapeDataString(encoded);
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Decoded URL: {decoded}");
            return Ok();
        }

        // TP26: Логирование исключения с user input
        public IActionResult TP26_ExceptionWithUserInput(string errorDetails)
        {
            try
            {
                throw new Exception(errorDetails);
            }
            catch (Exception ex)
            {
                // ruleid: csharp_log_injection_Rule-LogInjection
                _logger.LogError(ex, $"Exception details: {errorDetails}");
            }
            return Ok();
        }

        // TP27: Логирование через Log.LogLevel
        public IActionResult TP27_LogWithLevel(string level, string message)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.Log(LogLevel.Information, $"Level: {level}, Message: {message}");
            return Ok();
        }

        // TP28: Логирование в файл напрямую
        public IActionResult TP28_FileWriteLog(string logEntry)
        {
            string logPath = @"C:\logs\app.log";
            // ruleid: csharp_log_injection_Rule-LogInjection
            System.IO.File.AppendAllText(logPath, $"Log: {logEntry}\n");
            return Ok();
        }

        // TP29: StreamWriter для лога
        public IActionResult TP29_StreamWriterLog(string message)
        {
            using (var writer = new System.IO.StreamWriter(@"C:\logs\app.log", true))
            {
                // ruleid: csharp_log_injection_Rule-LogInjection
                writer.WriteLine($"Info: {message}");
            }
            return Ok();
        }

        // TP30: Многострочный log injection
        public IActionResult TP30_MultilineInjection(string userInput)
        {
            string maliciousInput = userInput + "\n[INFO] Fake log entry\n[ERROR] System compromised";
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation(maliciousInput);
            return Ok();
        }

        // TP31: JSON сериализация user input в лог
        public IActionResult TP31_JsonInLog(string userData)
        {
            var logObject = new { UserInput = userData, Timestamp = DateTime.Now };
            string json = System.Text.Json.JsonSerializer.Serialize(logObject);
            // ruleid: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation(json);
            return Ok();
        }

        // TP32: Serilog с форматированием
        public IActionResult TP32_SerilogFormat(string template, string value)
        {
            // ruleid: csharp_log_injection_Rule-LogInjection
            _serilog.Information($"Template: {template}, Value: {value}");
            return Ok();
        }

        // ---------- False Positive (rule should NOT trigger) ----------

        // FP1: Константное сообщение
        public IActionResult FP1_ConstantLog()
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation("Application started successfully");
            return Ok();
        }

        // FP2: Логирование с параметрами (структурированное логирование)
        public IActionResult FP2_StructuredLogging(string username)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation("User {Username} logged in", username);
            return Ok();
        }

        // FP3: Serilog с параметрами
        public IActionResult FP3_SerilogStructured(string userId)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _serilog.Information("User {UserId} performed action", userId);
            return Ok();
        }

        // FP4: NLog с параметрами
        public IActionResult FP4_NLogStructured(string email)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _nlogger.Info("Email {Email} sent", email);
            return Ok();
        }

        // FP5: log4net с форматированием через параметры
        public IActionResult FP5_Log4NetFormatted(string name)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _log4net.InfoFormat("User {0} logged in", name);
            return Ok();
        }

        // FP6: Экранирование спецсимволов
        public IActionResult FP6_EscapedLog(string userInput)
        {
            string safeInput = userInput.Replace("\n", "\\n").Replace("\r", "\\r");
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User input: {safeInput}");
            return Ok();
        }

        // FP7: Валидация через Regex
        public IActionResult FP7_RegexValidation(string userInput)
        {
            if (!Regex.IsMatch(userInput, @"^[a-zA-Z0-9\s]+$"))
            {
                return BadRequest("Invalid input");
            }
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Valid input: {userInput}");
            return Ok();
        }

        // FP8: JSON сериализация с экранированием
        public IActionResult FP8_JsonEscapedLog(string userInput)
        {
            var safeObject = new { Input = userInput };
            string json = System.Text.Json.JsonSerializer.Serialize(safeObject);
            // JSON автоматически экранирует спецсимволы
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation(json);
            return Ok();
        }

        // FP9: Логирование через EventSource (структурированное)
        public IActionResult FP9_EventSourceLog(string data)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            System.Diagnostics.Tracing.EventSource.Write("Event", new { Data = data });
            return Ok();
        }

        // FP10: Логирование GUID (безопасно)
        public IActionResult FP10_GuidLog()
        {
            Guid id = Guid.NewGuid();
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Generated ID: {id}");
            return Ok();
        }

        // FP11: Логирование числовых значений
        public IActionResult FP11_NumericLog(int userId, decimal amount)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"User {userId} transferred {amount:C}");
            return Ok();
        }

        // FP12: Логирование DateTime
        public IActionResult FP12_DateTimeLog(DateTime timestamp)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Timestamp: {timestamp:yyyy-MM-dd HH:mm:ss}");
            return Ok();
        }

        // FP13: Логирование enum значения
        public IActionResult FP13_EnumLog(LogLevel level)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Log level: {level}");
            return Ok();
        }

        // FP14: Логирование через ILogger.BeginScope
        public IActionResult FP14_ScopeLogging(string correlationId)
        {
            using (_logger.BeginScope(new { CorrelationId = correlationId }))
            {
                // ok: csharp_log_injection_Rule-LogInjection
                _logger.LogInformation("Processing request");
                return Ok();
            }
        }

        // FP15: Serilog с destructuring объектов
        public IActionResult FP15_SerilogDestructuring(UserModel user)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            _serilog.Information("User {@User} logged in", user);
            return Ok();
        }

        // FP16: Логирование через Audit.NET (структурированное)
        public IActionResult FP16_AuditLog(string action)
        {
            // ok: csharp_log_injection_Rule-LogInjection
            Audit.Core.Configuration.Setup()
                .UseConsole();
            AuditScope.Log("Action", new { Action = action });
            return Ok();
        }

        // FP17: Логирование только hash значения
        public IActionResult FP17_HashLog(string sensitiveData)
        {
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(sensitiveData));
                string hashString = Convert.ToBase64String(hash);
                // ok: csharp_log_injection_Rule-LogInjection
                _logger.LogInformation($"Data hash: {hashString}");
            }
            return Ok();
        }

        // FP18: Логирование через специальный safe wrapper
        public IActionResult FP18_SafeLogger(string userInput)
        {
            var safeLogger = new SafeLogger(_logger);
            // ok: csharp_log_injection_Rule-LogInjection
            safeLogger.LogUserInput(userInput);
            return Ok();
        }

        // FP19: Условное логирование с константой
        public IActionResult FP19_ConditionalLog(bool isError, string userInput)
        {
            if (isError)
            {
                // ok: csharp_log_injection_Rule-LogInjection
                _logger.LogError("An error occurred");
            }
            else
            {
                // ok: csharp_log_injection_Rule-LogInjection
                _logger.LogInformation($"User input length: {userInput?.Length ?? 0}");
            }
            return Ok();
        }

        // FP20: Логирование без user input
        public IActionResult FP20_NoUserInputLog()
        {
            var stats = new { Requests = 100, Errors = 5 };
            // ok: csharp_log_injection_Rule-LogInjection
            _logger.LogInformation($"Stats: {stats.Requests} requests, {stats.Errors} errors");
            return Ok();
        }
    }

    // Модели и вспомогательные классы
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class UserModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
    }

    public class SafeLogger
    {
        private readonly ILogger _logger;
        
        public SafeLogger(ILogger logger)
        {
            _logger = logger;
        }
        
        public void LogUserInput(string input)
        {
            string safeInput = input.Replace("\n", "\\n").Replace("\r", "\\r");
            _logger.LogInformation($"User input: {safeInput}");
        }
    }
}