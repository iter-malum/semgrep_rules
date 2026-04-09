using System;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

public class CookieHttpOnlyTestCases
{
    private readonly HttpResponse _response;
    private readonly HttpResponse _aspNetCoreResponse;

    public CookieHttpOnlyTestCases(HttpResponse response, HttpResponse aspNetCoreResponse)
    {
        _response = response;
        _aspNetCoreResponse = aspNetCoreResponse;
    }

    // ---------- True Positive (rule should trigger) ----------

    // ASP.NET Framework - HttpOnly явно false
    public void TP_HttpCookie_HttpOnlyFalse_Explicit()
    {
        HttpCookie cookie = new HttpCookie("SessionId", "value123");
        cookie.HttpOnly = false;
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - HttpOnly не установлен (default false)
    public void TP_HttpCookie_HttpOnlyMissing()
    {
        HttpCookie cookie = new HttpCookie("AuthToken", "token456");
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - HttpOnly установлен позже
    public void TP_HttpCookie_HttpOnlySetLaterToFalse()
    {
        HttpCookie cookie = new HttpCookie("UserData", "data789");
        cookie.Secure = true;
        cookie.HttpOnly = false;
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Core - CookieOptions с HttpOnly = false
    public void TP_AspNetCore_CookieOptions_HttpOnlyFalse()
    {
        var options = new CookieOptions
        {
            HttpOnly = false,
            Secure = true
        };
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("SessionToken", "token123", options);
    }

    // ASP.NET Core - CookieOptions без установки HttpOnly (default false)
    public void TP_AspNetCore_CookieOptions_HttpOnlyMissing()
    {
        var options = new CookieOptions
        {
            Secure = true
        };
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("AuthCookie", "auth456", options);
    }

    // ASP.NET Core - прямой Append без параметров
    public void TP_AspNetCore_AppendWithoutOptions()
    {
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("SimpleCookie", "value789");
    }

    // ASP.NET Core - Response.Cookies.Append (без Context)
    public void TP_AspNetCore_ResponseCookiesAppend_HttpOnlyFalse()
    {
        var options = new CookieOptions { HttpOnly = false };
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        Response.Cookies.Append("UserToken", "token999", options);
    }

    // ASP.NET Core - Context.Response.Cookies.Append
    public void TP_AspNetCore_ContextResponseCookiesAppend_WithoutHttpOnly()
    {
        var context = new DefaultHttpContext();
        var options = new CookieOptions();
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        context.Response.Cookies.Append("ContextCookie", "context123", options);
    }

    // ASP.NET Core - через переменную Response
    public void TP_AspNetCore_ResponseVariable_HttpOnlyFalse()
    {
        var response = _aspNetCoreResponse;
        var options = new CookieOptions { HttpOnly = false };
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        response.Cookies.Append("VariableCookie", "var456", options);
    }

    // ASP.NET Core - CookieOptions создан отдельно, HttpOnly = false
    public void TP_AspNetCore_CookieOptionsSeparate_HttpOnlyFalse()
    {
        var options = new CookieOptions();
        options.HttpOnly = false;
        options.Secure = true;
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("SeparateCookie", "sep789", options);
    }

    // ASP.NET Core - множественные cookies с проблемой
    public void TP_AspNetCore_MultipleCookies_SomeWithoutHttpOnly()
    {
        var options1 = new CookieOptions { HttpOnly = true, Secure = true };
        _aspNetCoreResponse.Cookies.Append("GoodCookie", "good123", options1);
        
        var options2 = new CookieOptions { Secure = true };
        // ruleid: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("BadCookie", "bad456", options2);
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // ASP.NET Framework - HttpOnly = true (безопасно)
    public void FP_HttpCookie_HttpOnlyTrue()
    {
        HttpCookie cookie = new HttpCookie("SessionId", "value123");
        cookie.HttpOnly = true;
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - HttpOnly установлен в true через свойство
    public void FP_HttpCookie_HttpOnlySetToTrue()
    {
        HttpCookie cookie = new HttpCookie("AuthToken", "token456");
        cookie.HttpOnly = true;
        cookie.Secure = true;
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Core - CookieOptions с HttpOnly = true
    public void FP_AspNetCore_CookieOptions_HttpOnlyTrue()
    {
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = true
        };
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("SessionToken", "token123", options);
    }

    // ASP.NET Core - явная установка HttpOnly = true после создания
    public void FP_AspNetCore_CookieOptions_HttpOnlySetLaterToTrue()
    {
        var options = new CookieOptions();
        options.HttpOnly = true;
        options.Secure = true;
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("SecureCookie", "secure789", options);
    }

    // ASP.NET Core - CookieOptions с инициализатором
    public void FP_AspNetCore_CookieOptions_WithInitializer()
    {
        var options = new CookieOptions { HttpOnly = true };
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Append("InitCookie", "init123", options);
    }

    // ASP.NET Core - через свойство HttpContext
    public void FP_AspNetCore_HttpContext_CookieWithHttpOnly()
    {
        var context = new DefaultHttpContext();
        var options = new CookieOptions { HttpOnly = true, Secure = true };
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        context.Response.Cookies.Append("ContextSecureCookie", "ctx456", options);
    }

    // Response.Cookies.Delete - не относится к созданию cookie
    public void FP_Response_DeleteCookie()
    {
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        _aspNetCoreResponse.Cookies.Delete("CookieToDelete");
    }

    // Non-cookie operations
    public void FP_NonCookie_Operations()
    {
        // ok: csharp_cookies_rule-CookieWithoutHttpOnlyFlag
        var header = _response.Headers["SomeHeader"];
    }
}