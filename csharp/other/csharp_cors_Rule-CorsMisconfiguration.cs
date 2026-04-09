using System;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace CORS_TestCases
{
    // ---------- True Positive (rule should trigger) ----------

    // TP1: Разрешить любой origin (AllowAnyOrigin)
    [EnableCors("AllowAnyOriginPolicy")]
    public class TP1_AnyOriginController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetSensitiveData()
        {
            return Ok(new { data = "sensitive" });
        }
    }

    // TP2: Разрешить любой origin через конкретный метод
    public class TP2_MethodWithAnyOriginController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [EnableCors("AllowAnyOrigin")]
        [HttpPost]
        public IActionResult UpdateUser([FromBody] UserModel user)
        {
            return Ok();
        }
    }

    // TP3: AllowAnyOrigin с AllowCredentials (опасная комбинация)
    [EnableCors("DangerousPolicy")]
    public class TP3_DangerousController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetUserProfile()
        {
            return Ok();
        }
    }

    // TP4: Динамический origin с SetIsOriginAllowedToAllowWildcardSubdomains
    public class TP4_DynamicOriginController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            Response.Headers.Add("Access-Control-Allow-Origin", "*");
            Response.Headers.Add("Access-Control-Allow-Credentials", "true");
            return Ok();
        }
    }

    // TP5: Wildcard subdomain (*.example.com) с credentials
    [EnableCors("WildcardSubdomainPolicy")]
    public class TP5_WildcardSubdomainController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP6: AllowAnyOrigin через глобальную конфигурацию
    public class TP6_GlobalAnyOriginController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetGlobalData()
        {
            return Ok();
        }
    }

    // TP7: AllowCredentials + AllowAnyOrigin в конфигурации
    [EnableCors("CredentialsWithAnyOrigin")]
    public class TP7_CredentialsAnyOriginController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetSecureData()
        {
            return Ok();
        }
    }

    // TP8: Установка заголовков вручную (опасно)
    public class TP8_ManualHeadersController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            HttpContext.Response.Headers["Access-Control-Allow-Origin"] = "*";
            HttpContext.Response.Headers["Access-Control-Allow-Credentials"] = "true";
            return Json(new { message = "Sensitive data" });
        }
    }

    // TP9: Установка заголовков через OnResultExecuting
    public class TP9_FilterAttribute : ActionFilterAttribute
    {
        public override void OnResultExecuting(ResultExecutingContext context)
        {
            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            context.HttpContext.Response.Headers["Access-Control-Allow-Origin"] = "*";
            base.OnResultExecuting(context);
        }
    }

    [TP9_FilterAttribute]
    public class TP9_Controller : Controller
    {
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP10: Origin из заголовка без валидации
    public class TP10_OriginReflectionController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            var origin = Request.Headers["Origin"].ToString();
            Response.Headers["Access-Control-Allow-Origin"] = origin;
            Response.Headers["Access-Control-Allow-Credentials"] = "true";
            return Ok();
        }
    }

    // TP11: Регулярное выражение для origin (небезопасно)
    [EnableCors("RegexOriginPolicy")]
    public class TP11_RegexOriginController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP12: AllowAnyOrigin с кэшированием CORS
    [EnableCors("CachedAnyOriginPolicy")]
    public class TP12_CachedAnyOriginController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP13: Null origin (небезопасно)
    public class TP13_NullOriginController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            Response.Headers["Access-Control-Allow-Origin"] = "null";
            Response.Headers["Access-Control-Allow-Credentials"] = "true";
            return Ok();
        }
    }

    // TP14: Credentials + wildcard через конфигурацию
    [EnableCors("WildcardCredentialsPolicy")]
    public class TP14_WildcardCredentialsController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP15: Несколько методов с разными опасными политиками
    public class TP15_MultipleMethodsController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [EnableCors("AllowAnyOrigin")]
        [HttpGet]
        public IActionResult GetPublic()
        {
            return Ok();
        }

        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [EnableCors("WildcardPolicy")]
        [HttpPost]
        public IActionResult UpdateData()
        {
            return Ok();
        }
    }

    // TP16: CORS middleware с AllowAnyOrigin
    public class TP16_MiddlewareAnyOriginController : Controller
    {
        [HttpGet]
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // TP17: SetIsOriginAllowedToAllowWildcardSubdomains с dangerous pattern
    [EnableCors("DangerousSubdomainPolicy")]
    public class TP17_DangerousSubdomainController : Controller
    {
        // ruleid: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // FP1: Без CORS (нет заголовков)
    public class FP1_NoCorsController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // FP2: Разрешены только конкретные origin
    [EnableCors("SpecificOriginsPolicy")]
    public class FP2_SpecificOriginsController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // FP3: Без AllowCredentials с AllowAnyOrigin (менее опасно, но все же риск)
    [EnableCors("AnyOriginNoCredentials")]
    public class FP3_AnyOriginNoCredentialsController : Controller
    {
        // ok: csharp_cors_Rule-CorsMisconfiguration
        [HttpGet]
        public IActionResult GetPublicData()
        {
            return Ok();
        }
    }

    // FP4: Правильная валидация origin через whitelist
    public class FP4_ValidatedOriginController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            var origin = Request.Headers["Origin"].ToString();
            var allowedOrigins = new[] { "https://example.com", "https://app.example.com" };
            
            if (allowedOrigins.Contains(origin))
            {
                Response.Headers["Access-Control-Allow-Origin"] = origin;
            }
            
            return Ok();
        }
    }

    // FP5: AllowAnyOrigin но только для публичных endpoint'ов (без sensitive data)
    [EnableCors("PublicApiPolicy")]
    public class FP5_PublicApiController : Controller
    {
        [HttpGet]
        [AllowAnonymous]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetPublicInfo()
        {
            return Ok(new { version = "1.0", status = "healthy" });
        }
    }

    // FP6: No credentials + specific origins
    [EnableCors("SecurePolicy")]
    public class FP6_SecureController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // FP7: Disabled CORS explicitly
    [DisableCors]
    public class FP7_DisabledCorsController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            return Ok();
        }
    }

    // FP8: Использование политики только для OPTIONS
    [EnableCors("PreflightOnlyPolicy")]
    public class FP8_PreflightOnlyController : Controller
    {
        [HttpOptions]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult Options()
        {
            return Ok();
        }
    }

    // FP9: Environment-specific CORS (development only)
    public class FP9_DevOnlyCorsController : Controller
    {
        [HttpGet]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetData()
        {
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            {
                Response.Headers["Access-Control-Allow-Origin"] = "*";
            }
            return Ok();
        }
    }

    // FP10: CORS для статических файлов (не sensitive)
    [EnableCors("StaticFilesPolicy")]
    public class FP10_StaticFilesController : Controller
    {
        [HttpGet("/images/{filename}")]
        // ok: csharp_cors_Rule-CorsMisconfiguration
        public IActionResult GetImage(string filename)
        {
            return PhysicalFile($"wwwroot/images/{filename}", "image/jpeg");
        }
    }

    // Настройки для Startup.cs (должны быть проанализированы)
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // TP конфигурации
            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAnyOriginPolicy", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });

            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("CredentialsWithAnyOrigin", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader()
                           .AllowCredentials();
                });
            });

            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("WildcardSubdomainPolicy", builder =>
                {
                    builder.SetIsOriginAllowedToAllowWildcardSubdomains()
                           .WithOrigins("https://*.example.com")
                           .AllowCredentials();
                });
            });

            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("RegexOriginPolicy", builder =>
                {
                    builder.SetIsOriginAllowed(origin => 
                        System.Text.RegularExpressions.Regex.IsMatch(origin, @"https://.*\.example\.com"))
                           .AllowCredentials();
                });
            });

            // FP конфигурации
            // ok: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("SpecificOriginsPolicy", builder =>
                {
                    builder.WithOrigins("https://example.com", "https://app.example.com")
                           .AllowAnyMethod()
                           .AllowAnyHeader()
                           .AllowCredentials();
                });
            });

            // ok: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("AnyOriginNoCredentials", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });

            // ok: csharp_cors_Rule-CorsMisconfiguration
            services.AddCors(options =>
            {
                options.AddPolicy("SecurePolicy", builder =>
                {
                    builder.WithOrigins("https://trusted.com")
                           .WithMethods("GET", "POST")
                           .AllowCredentials();
                });
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            // TP: Глобальный CORS с AllowAnyOrigin
            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            app.UseCors(builder => builder.AllowAnyOrigin());

            // TP: Глобальный CORS с AllowAnyOrigin и AllowCredentials
            // ruleid: csharp_cors_Rule-CorsMisconfiguration
            app.UseCors(builder => builder.AllowAnyOrigin().AllowCredentials());

            // FP: Глобальный CORS с конкретными origin
            // ok: csharp_cors_Rule-CorsMisconfiguration
            app.UseCors(builder => builder.WithOrigins("https://example.com"));

            // FP: Использование именованной политики
            // ok: csharp_cors_Rule-CorsMisconfiguration
            app.UseCors("SpecificOriginsPolicy");
        }
    }
}

// Модели
public class UserModel
{
    public string Username { get; set; }
    public string Email { get; set; }
}