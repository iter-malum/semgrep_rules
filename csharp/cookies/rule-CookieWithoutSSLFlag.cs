using System;
using System.Web;
using Microsoft.AspNetCore.Http;

public class CookieSSLTestCases
{
    private readonly HttpResponse _response;
    private readonly HttpResponse _aspNetCoreResponse;

    public CookieSSLTestCases(HttpResponse response, HttpResponse aspNetCoreResponse)
    {
        _response = response;
        _aspNetCoreResponse = aspNetCoreResponse;
    }

    // ---------- True Positive (rule should trigger) ----------

    // ASP.NET Framework - Secure явно false
    public void TP_HttpCookie_SecureFalse_Explicit()
    {
        HttpCookie cookie = new HttpCookie("SessionId", "value123");
        cookie.Secure = false;
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - Secure не установлен (default false)
    public void TP_HttpCookie_SecureMissing()
    {
        HttpCookie cookie = new HttpCookie("AuthToken", "token456");
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - Secure установлен позже в false
    public void TP_HttpCookie_SecureSetLaterToFalse()
    {
        HttpCookie cookie = new HttpCookie("UserData", "data789");
        cookie.HttpOnly = true;
        cookie.Secure = false;
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - Secure = false, HttpOnly = true
    public void TP_HttpCookie_SecureFalse_HttpOnlyTrue()
    {
        HttpCookie cookie = new HttpCookie("MixedCookie", "mixed123");
        cookie.HttpOnly = true;
        cookie.Secure = false;
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Core - CookieOptions с Secure = false
    public void TP_AspNetCore_CookieOptions_SecureFalse()
    {
        var options = new CookieOptions
        {
            Secure = false,
            HttpOnly = true
        };
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("SessionToken", "token123", options);
    }

    // ASP.NET Core - CookieOptions без установки Secure (default false)
    public void TP_AspNetCore_CookieOptions_SecureMissing()
    {
        var options = new CookieOptions
        {
            HttpOnly = true
        };
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("AuthCookie", "auth456", options);
    }

    // ASP.NET Core - прямой Append без параметров
    public void TP_AspNetCore_AppendWithoutOptions_SecureMissing()
    {
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("SimpleCookie", "value789");
    }

    // ASP.NET Core - Response.Cookies.Append без Secure
    public void TP_AspNetCore_ResponseCookiesAppend_SecureFalse()
    {
        var options = new CookieOptions { Secure = false };
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        Response.Cookies.Append("UserToken", "token999", options);
    }

    // ASP.NET Core - Context.Response.Cookies.Append без Secure
    public void TP_AspNetCore_ContextResponseCookiesAppend_WithoutSecure()
    {
        var context = new DefaultHttpContext();
        var options = new CookieOptions();
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        context.Response.Cookies.Append("ContextCookie", "context123", options);
    }

    // ASP.NET Core - через переменную Response
    public void TP_AspNetCore_ResponseVariable_SecureFalse()
    {
        var response = _aspNetCoreResponse;
        var options = new CookieOptions { Secure = false };
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        response.Cookies.Append("VariableCookie", "var456", options);
    }

    // ASP.NET Core - CookieOptions создан отдельно, Secure = false
    public void TP_AspNetCore_CookieOptionsSeparate_SecureFalse()
    {
        var options = new CookieOptions();
        options.Secure = false;
        options.HttpOnly = true;
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("SeparateCookie", "sep789", options);
    }

    // ASP.NET Core - множественные cookies с проблемой SSL
    public void TP_AspNetCore_MultipleCookies_SomeWithoutSecure()
    {
        var options1 = new CookieOptions { Secure = true, HttpOnly = true };
        _aspNetCoreResponse.Cookies.Append("GoodCookie", "good123", options1);
        
        var options2 = new CookieOptions { HttpOnly = true };
        // ruleid: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("BadCookie", "bad456", options2);
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // ASP.NET Framework - Secure = true (безопасно)
    public void FP_HttpCookie_SecureTrue()
    {
        HttpCookie cookie = new HttpCookie("SessionId", "value123");
        cookie.Secure = true;
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Framework - Secure и HttpOnly оба true
    public void FP_HttpCookie_BothFlagsTrue()
    {
        HttpCookie cookie = new HttpCookie("AuthToken", "token456");
        cookie.HttpOnly = true;
        cookie.Secure = true;
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _response.SetCookie(cookie);
    }

    // ASP.NET Core - CookieOptions с Secure = true
    public void FP_AspNetCore_CookieOptions_SecureTrue()
    {
        var options = new CookieOptions
        {
            Secure = true,
            HttpOnly = true
        };
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("SessionToken", "token123", options);
    }

    // ASP.NET Core - явная установка Secure = true после создания
    public void FP_AspNetCore_CookieOptions_SecureSetLaterToTrue()
    {
        var options = new CookieOptions();
        options.Secure = true;
        options.HttpOnly = true;
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("SecureCookie", "secure789", options);
    }

    // ASP.NET Core - CookieOptions с инициализатором Secure = true
    public void FP_AspNetCore_CookieOptions_WithInitializerSecure()
    {
        var options = new CookieOptions { Secure = true };
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Append("InitCookie", "init123", options);
    }

    // ASP.NET Core - через свойство HttpContext
    public void FP_AspNetCore_HttpContext_CookieWithSecure()
    {
        var context = new DefaultHttpContext();
        var options = new CookieOptions { Secure = true, HttpOnly = true };
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        context.Response.Cookies.Append("ContextSecureCookie", "ctx456", options);
    }

    // ASP.NET Core - только Secure = true, без HttpOnly (безопасно для SSL)
    public void FP_AspNetCore_SecureOnly_HttpOnlyMissing()
    {
        var options = new CookieOptions { Secure = true };
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag - SSL флаг установлен
        _aspNetCoreResponse.Cookies.Append("SecureOnlyCookie", "secure456", options);
    }

    // Response.Cookies.Delete - не относится к созданию cookie
    public void FP_Response_DeleteCookie_Secure()
    {
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        _aspNetCoreResponse.Cookies.Delete("CookieToDelete");
    }

    // Non-cookie operations
    public void FP_NonCookie_Operations_Secure()
    {
        // ok: csharp_cookies_rule-CookieWithoutSSLFlag
        var header = _response.Headers["SomeHeader"];
    }
}