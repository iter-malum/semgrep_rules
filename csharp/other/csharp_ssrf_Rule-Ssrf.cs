using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Net.Sockets;
using System.Xml;
using System.Text;
using RestSharp;
using Flurl.Http;
using System.Net.Http.Headers;

public class SsrfTestCases
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly HttpClient _httpClient;
    private readonly IWebHostEnvironment _env;

    public SsrfTestCases(IHttpClientFactory httpClientFactory, HttpClient httpClient, IWebHostEnvironment env)
    {
        _httpClientFactory = httpClientFactory;
        _httpClient = httpClient;
        _env = env;
    }

    // ---------- True Positive (rule should trigger) ----------

    // TP1: WebClient.DownloadString с user input
    public IActionResult TP1_WebClientDownload(string url)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            string result = client.DownloadString(url);
            return Content(result);
        }
    }

    // TP2: WebClient.UploadString с user input
    public IActionResult TP2_WebClientUpload(string url, string data)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            string result = client.UploadString(url, data);
            return Content(result);
        }
    }

    // TP3: HttpClient.GetStringAsync с интерполяцией
    public async Task<IActionResult> TP3_HttpClientGet(string apiEndpoint)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        string url = $"https://api.example.com/{apiEndpoint}";
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // TP4: HttpClient.GetAsync с конкатенацией
    public async Task<IActionResult> TP4_HttpClientGetAsync(string resourcePath)
    {
        string url = "http://internal.service/" + resourcePath;
        // ruleid: csharp_ssrf_Rule-Ssrf
        HttpResponseMessage response = await _httpClient.GetAsync(url);
        string result = await response.Content.ReadAsStringAsync();
        return Content(result);
    }

    // TP5: HttpClient.SendAsync с user input
    public async Task<IActionResult> TP5_HttpClientSend(string targetUrl)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, targetUrl);
        // ruleid: csharp_ssrf_Rule-Ssrf
        HttpResponseMessage response = await _httpClient.SendAsync(request);
        return Content(await response.Content.ReadAsStringAsync());
    }

    // TP6: HttpWebRequest с user input
    public IActionResult TP6_HttpWebRequest(string url)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
        {
            string result = reader.ReadToEnd();
            return Content(result);
        }
    }

    // TP7: WebRequest.Create с user input
    public IActionResult TP7_WebRequestCreate(string callbackUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        WebRequest request = WebRequest.Create(callbackUrl);
        using (WebResponse response = request.GetResponse())
        using (StreamReader reader = new StreamReader(response.GetResponseStream()))
        {
            return Content(reader.ReadToEnd());
        }
    }

    // TP8: RestSharp RestClient.Execute
    public IActionResult TP8_RestSharpExecute(string userUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        var client = new RestClient(userUrl);
        var request = new RestRequest();
        var response = client.Execute(request);
        return Content(response.Content);
    }

    // TP9: Flurl.Http GetAsync
    public async Task<IActionResult> TP9_FlurlHttp(string userInput)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        var result = await userInput.GetAsync();
        string content = await result.GetStringAsync();
        return Content(content);
    }

    // TP10: Flurl.Http PostAsync
    public async Task<IActionResult> TP10_FlurlPost(string webhookUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        var result = await webhookUrl.PostJsonAsync(new { data = "test" });
        return Ok();
    }

    // TP11: HttpClient из IHttpClientFactory с user input
    public async Task<IActionResult> TP11_HttpClientFactory(string externalUrl)
    {
        var client = _httpClientFactory.CreateClient();
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await client.GetStringAsync(externalUrl);
        return Content(result);
    }

    // TP12: WebClient.DownloadData с user input
    public IActionResult TP12_DownloadData(string imageUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            byte[] data = client.DownloadData(imageUrl);
            return File(data, "image/jpeg");
        }
    }

    // TP13: HttpWebRequest с интерполяцией строк
    public IActionResult TP13_HttpWebRequestInterpolation(string subdomain)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        string url = $"http://{subdomain}.internal.service.com/api/data";
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        using (var response = request.GetResponse())
        {
            return Ok();
        }
    }

    // TP14: Uri из user input
    public async Task<IActionResult> TP14_UriFromUserInput(string userSuppliedUri)
    {
        Uri uri = new Uri(userSuppliedUri);
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(uri);
        return Content(result);
    }

    // TP15: Base64 encoded URL
    public IActionResult TP15_Base64Url(string encodedUrl)
    {
        byte[] data = Convert.FromBase64String(encodedUrl);
        string url = Encoding.UTF8.GetString(data);
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            string result = client.DownloadString(url);
            return Content(result);
        }
    }

    // TP16: URL из параметров запроса
    public async Task<IActionResult> TP16_FromQueryParam([FromQuery] string callback)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(callback);
        return Content(result);
    }

    // TP17: URL из тела запроса
    [HttpPost]
    public async Task<IActionResult> TP17_FromBody([FromBody] WebhookRequest request)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(request.WebhookUrl);
        return Content(result);
    }

    // TP18: URL из Route параметра
    [HttpGet("proxy/{*url}")]
    public async Task<IActionResult> TP18_FromRoute(string url)
    {
        string decodedUrl = Uri.UnescapeDataString(url);
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(decodedUrl);
        return Content(result);
    }

    // TP19: Многоступенчатая обработка URL
    public async Task<IActionResult> TP19_MultipleSteps(string endpoint)
    {
        string baseUrl = "https://api.example.com/";
        string fullUrl = string.Concat(baseUrl, endpoint);
        string finalUrl = fullUrl.Trim();
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(finalUrl);
        return Content(result);
    }

    // TP20: StringBuilder URL construction
    public IActionResult TP20_StringBuilderUrl(string path)
    {
        var sb = new StringBuilder("http://internal.api/");
        sb.Append(path);
        sb.Append("/data");
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            string result = client.DownloadString(sb.ToString());
            return Content(result);
        }
    }

    // TP21: WebRequest with POST method
    public IActionResult TP21_WebRequestPost(string webhookUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        WebRequest request = WebRequest.Create(webhookUrl);
        request.Method = "POST";
        byte[] data = Encoding.UTF8.GetBytes("test data");
        request.GetRequestStream().Write(data, 0, data.Length);
        using (WebResponse response = request.GetResponse())
        {
            return Ok();
        }
    }

    // TP22: HttpClient with custom headers
    public async Task<IActionResult> TP22_HttpClientWithHeaders(string apiUrl)
    {
        using (var client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("X-Custom-Header", "value");
            // ruleid: csharp_ssrf_Rule-Ssrf
            string result = await client.GetStringAsync(apiUrl);
            return Content(result);
        }
    }

    // TP23: HttpWebRequest with credentials
    public IActionResult TP23_RequestWithCredentials(string resourceUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(resourceUrl);
        request.Credentials = CredentialCache.DefaultCredentials;
        using (var response = request.GetResponse())
        {
            return Ok();
        }
    }

    // TP24: XmlDocument.Load with user input URL
    public IActionResult TP24_XmlDocumentLoad(string xmlUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        XmlDocument doc = new XmlDocument();
        doc.Load(xmlUrl);
        return Content(doc.InnerXml);
    }

    // TP25: XDocument.Load with user input
    public IActionResult TP25_XDocumentLoad(string externalXmlSource)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        var doc = System.Xml.Linq.XDocument.Load(externalXmlSource);
        return Content(doc.ToString());
    }

    // TP26: Url encoded path traversal in URL
    public async Task<IActionResult> TP26_EncodedUrl(string userInput)
    {
        string encoded = Uri.EscapeDataString(userInput);
        string url = $"http://internal.service/fetch?url={encoded}";
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // TP27: Redirect to user controlled URL
    public IActionResult TP27_RedirectToUserUrl(string returnUrl)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf - это не прямой запрос, но опасный редирект
        return Redirect(returnUrl);
    }

    // TP28: Local file access via file:// protocol
    public async Task<IActionResult> TP28_FileProtocol(string filePath)
    {
        string url = $"file:///{filePath}";
        // ruleid: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // TP29: FTP protocol access
    public IActionResult TP29_FtpProtocol(string ftpPath)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        WebRequest request = WebRequest.Create($"ftp://{ftpPath}");
        using (WebResponse response = request.GetResponse())
        {
            return Ok();
        }
    }

    // TP30: Net.Sockets.TcpClient (low-level SSRF)
    public async Task<IActionResult> TP30_TcpClientConnection(string host, int port)
    {
        // ruleid: csharp_ssrf_Rule-Ssrf
        using (TcpClient client = new TcpClient())
        {
            await client.ConnectAsync(host, port);
            return Ok($"Connected to {host}:{port}");
        }
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // FP1: Запрос к разрешенному домену из конфигурации
    public async Task<IActionResult> FP1_AllowedDomain()
    {
        string apiUrl = Configuration.GetValue<string>("AllowedApiUrl");
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(apiUrl);
        return Content(result);
    }

    // FP2: URL из ресурсов приложения (константа)
    public async Task<IActionResult> FP2_ConstantUrl()
    {
        const string url = "https://trusted-api.example.com/data";
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // FP3: URL с валидацией через Whitelist
    public async Task<IActionResult> FP3_WhitelistValidation(string userUrl)
    {
        string[] allowedDomains = { "api.example.com", "cdn.example.com", "data.example.org" };
        
        Uri uri = new Uri(userUrl);
        if (!allowedDomains.Contains(uri.Host))
        {
            return BadRequest("Domain not allowed");
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(userUrl);
        return Content(result);
    }

    // FP4: URL с проверкой на внутренние IP
    public async Task<IActionResult> FP4_InternalIpCheck(string url)
    {
        Uri uri = new Uri(url);
        IPAddress[] addresses = Dns.GetHostAddresses(uri.Host);
        
        foreach (var ip in addresses)
        {
            if (IsInternalIp(ip))
            {
                return BadRequest("Internal IP addresses are not allowed");
            }
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // FP5: Использование HttpClient с BaseAddress
    public async Task<IActionResult> FP5_BaseAddressClient(string endpoint)
    {
        using (var client = new HttpClient())
        {
            client.BaseAddress = new Uri("https://trusted-api.example.com");
            // endpoint проверен и не содержит ".." или перенаправлений
            if (endpoint.Contains("..") || endpoint.Contains("//"))
            {
                return BadRequest();
            }
            // ok: csharp_ssrf_Rule-Ssrf
            string result = await client.GetStringAsync(endpoint);
            return Content(result);
        }
    }

    // FP6: URL из JWT токена (безопасный источник)
    public async Task<IActionResult> FP6_FromJwtToken(string token)
    {
        // Предполагаем, что URL из валидного JWT
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        string callbackUrl = jwtToken.Claims.First(c => c.Type == "callback_url").Value;
        
        // Валидация домена
        Uri uri = new Uri(callbackUrl);
        if (uri.Host != "trusted.com")
        {
            return BadRequest();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(callbackUrl);
        return Content(result);
    }

    // FP7: Запрос к локальному файлу (но только в разрешенной директории)
    public IActionResult FP7_LocalFileAllowed(string fileName)
    {
        string basePath = _env.WebRootPath;
        string fullPath = Path.GetFullPath(Path.Combine(basePath, fileName));
        
        if (!fullPath.StartsWith(basePath))
        {
            return BadRequest();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf - это file read, не SSRF
        string content = System.IO.File.ReadAllText(fullPath);
        return Content(content);
    }

    // FP8: WebRequest с URL из appsettings
    public IActionResult FP8_ConfigUrl()
    {
        string healthCheckUrl = Configuration.GetValue<string>("HealthCheckEndpoint");
        // ok: csharp_ssrf_Rule-Ssrf
        WebRequest request = WebRequest.Create(healthCheckUrl);
        request.Method = "HEAD";
        using (WebResponse response = request.GetResponse())
        {
            return Ok();
        }
    }

    // FP9: RestSharp с предустановленным BaseUrl
    public IActionResult FP9_RestSharpBaseUrl(string resource)
    {
        var client = new RestClient("https://trusted-api.example.com");
        var request = new RestRequest(resource, Method.Get);
        
        // resource проверен
        if (resource.Contains("/") || resource.Contains("\\"))
        {
            return BadRequest();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        var response = client.Execute(request);
        return Content(response.Content);
    }

    // FP10: HttpClient через IHttpClientFactory с именованным клиентом
    public async Task<IActionResult> FP10_NamedHttpClient(string id)
    {
        var client = _httpClientFactory.CreateClient("TrustedApi");
        // id проверен и не содержит URL
        if (!int.TryParse(id, out int userId))
        {
            return BadRequest();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await client.GetStringAsync($"/api/users/{userId}");
        return Content(result);
    }

    // FP11: Использование IP адреса из конфигурации
    public async Task<IActionResult> FP11_ConfigIpAddress()
    {
        string internalApiIp = Configuration.GetValue<string>("InternalApiIp");
        string url = $"http://{internalApiIp}:8080/api/health";
        // ok: csharp_ssrf_Rule-Ssrf
        string result = await _httpClient.GetStringAsync(url);
        return Content(result);
    }

    // FP12: Запрос через прокси (не SSRF, если прокси контролируется)
    public async Task<IActionResult> FP12_ProxyRequest(string externalUrl)
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy("http://proxy.company.com:8080"),
            UseProxy = true
        };
        
        using (var client = new HttpClient(handler))
        {
            // Внешний URL проходит через корпоративный прокси
            // ok: csharp_ssrf_Rule-Ssrf
            string result = await client.GetStringAsync(externalUrl);
            return Content(result);
        }
    }

    // FP13: URL с проверкой схемы
    public async Task<IActionResult> FP13_SchemeValidation(string url)
    {
        Uri uri = new Uri(url);
        if (uri.Scheme != Uri.UriSchemeHttps)
        {
            return BadRequest("Only HTTPS URLs are allowed");
        }
        
        if (uri.Host.EndsWith(".example.com") || uri.Host.EndsWith(".trusted.com"))
        {
            // ok: csharp_ssrf_Rule-Ssrf
            string result = await _httpClient.GetStringAsync(url);
            return Content(result);
        }
        
        return BadRequest();
    }

    // FP14: Использование HttpWebRequest с предварительной валидацией
    public IActionResult FP14_ValidatedRequest(string userUrl)
    {
        if (!Uri.IsWellFormedUriString(userUrl, UriKind.Absolute))
        {
            return BadRequest();
        }
        
        Uri uri = new Uri(userUrl);
        if (uri.Host != "api.trusted-service.com")
        {
            return BadRequest();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
        using (var response = request.GetResponse())
        {
            return Ok();
        }
    }

    // FP15: WebClient с URL из безопасного хранилища
    public IActionResult FP15_SecureStorageUrl()
    {
        // URL из Azure Key Vault или другого secure storage
        string webhookUrl = SecureStorage.GetSecret("WebhookUrl");
        // ok: csharp_ssrf_Rule-Ssrf
        using (WebClient client = new WebClient())
        {
            client.UploadString(webhookUrl, "{}");
            return Ok();
        }
    }

    // FP16: Использование Path.Combine для локальных файлов (не SSRF)
    public IActionResult FP16_LocalFileCombine(string fileName)
    {
        string filePath = Path.Combine(_env.ContentRootPath, "Data", fileName);
        if (!System.IO.File.Exists(filePath))
        {
            return NotFound();
        }
        
        // ok: csharp_ssrf_Rule-Ssrf - это file read, не HTTP request
        string content = System.IO.File.ReadAllText(filePath);
        return Content(content);
    }
}

public class WebhookRequest
{
    public string WebhookUrl { get; set; }
    public string Payload { get; set; }
}

public static class Configuration
{
    public static string GetValue<T>(string key) => "";
}

public static class SecureStorage
{
    public static string GetSecret(string key) => "";
}

public static class IsInternalIpHelper
{
    public static bool IsInternalIp(IPAddress ip) => false;
}