using System;
using System.IO;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.IO.Compression;
using System.Security.Cryptography;

public class PathTraversalTestCases
{
    private readonly IWebHostEnvironment _env;
    private readonly HttpRequest _request;
    private readonly HttpResponse _response;

    // ---------- True Positive (rule should trigger) ----------

    // TP1: Прямое использование user input в Path.Combine
    public IActionResult TP1_DownloadFile(string filename)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string filePath = Path.Combine(_env.WebRootPath, "uploads", filename);
        return PhysicalFile(filePath, "application/octet-stream");
    }

    // TP2: Конкатенация строк с user input
    public IActionResult TP2_ReadFile(string fileName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = _env.WebRootPath + "/files/" + fileName;
        string content = System.IO.File.ReadAllText(path);
        return Content(content);
    }

    // TP3: Интерполяция строк
    public IActionResult TP3_GetDocument(string docId)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string fullPath = $"{_env.WebRootPath}/documents/{docId}.pdf";
        return PhysicalFile(fullPath, "application/pdf");
    }

    // TP4: Path.Combine с интерполяцией
    public IActionResult TP4_GetImage(string imageName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, $"images/{imageName}");
        return PhysicalFile(path, "image/jpeg");
    }

    // TP5: User input в File.ReadAllText
    public string TP5_ReadConfig(string configFile)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        return System.IO.File.ReadAllText(configFile);
    }

    // TP6: User input в File.Delete
    public IActionResult TP6_DeleteFile(string fileToDelete)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        System.IO.File.Delete(fileToDelete);
        return Ok();
    }

    // TP7: User input в Directory.GetFiles
    public string[] TP7_ListFiles(string subDirectory)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        return Directory.GetFiles(subDirectory);
    }

    // TP8: User input в File.Copy
    public IActionResult TP8_CopyFile(string sourceFile, string destFile)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        System.IO.File.Copy(sourceFile, destFile);
        return Ok();
    }

    // TP9: User input в File.Move
    public IActionResult TP9_MoveFile(string oldPath, string newPath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        System.IO.File.Move(oldPath, newPath);
        return Ok();
    }

    // TP10: User input в Directory.CreateDirectory
    public IActionResult TP10_CreateDirectory(string dirName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        Directory.CreateDirectory(dirName);
        return Ok();
    }

    // TP11: User input в File.AppendAllText
    public IActionResult TP11_AppendLog(string logFile, string content)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        System.IO.File.AppendAllText(logFile, content);
        return Ok();
    }

    // TP12: User input в FileStream
    public IActionResult TP12_OpenFileStream(string fileName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        using (var fs = new FileStream(fileName, FileMode.Open))
        {
            return File(fs, "application/octet-stream");
        }
    }

    // TP13: User input в StreamReader
    public string TP13_ReadStreamReader(string filePath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        using (var sr = new StreamReader(filePath))
        {
            return sr.ReadToEnd();
        }
    }

    // TP14: User input после нормализации пути
    public IActionResult TP14_GetFileAfterNormalization(string fileName)
    {
        string path = Path.GetFullPath(Path.Combine(_env.WebRootPath, fileName));
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        return PhysicalFile(path, "text/plain");
    }

    // TP15: User input с заменой слешей
    public IActionResult TP15_WithReplace(string fileName)
    {
        string cleanName = fileName.Replace("/", "").Replace("\\", "");
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "uploads", cleanName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // TP16: Многоступенчатая обработка с StringBuilder
    public IActionResult TP16_StringBuilderPath(string folder, string file)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(_env.WebRootPath);
        sb.Append("/");
        sb.Append(folder);
        sb.Append("/");
        sb.Append(file);
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = sb.ToString();
        return PhysicalFile(path, "text/plain");
    }

    // TP17: User input в ZipFile.ExtractToDirectory
    public IActionResult TP17_ExtractZip(string zipPath, string extractPath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        ZipFile.ExtractToDirectory(zipPath, extractPath);
        return Ok();
    }

    // TP18: User input в File.Create
    public IActionResult TP18_CreateFile(string filePath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        using (var fs = System.IO.File.Create(filePath))
        {
            return Ok();
        }
    }

    // TP19: User input в FileInfo
    public IActionResult TP19_FileInfoOperations(string fileName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        FileInfo fileInfo = new FileInfo(fileName);
        string content = System.IO.File.ReadAllText(fileInfo.FullName);
        return Content(content);
    }

    // TP20: User input в DirectoryInfo
    public IActionResult TP20_DirectoryInfoOperations(string dirPath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        DirectoryInfo dirInfo = new DirectoryInfo(dirPath);
        var files = dirInfo.GetFiles();
        return Ok(files);
    }

    // TP21: Path.GetFullPath с user input
    public IActionResult TP21_GetFullPath(string userPath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string fullPath = Path.GetFullPath(userPath);
        return PhysicalFile(fullPath, "text/plain");
    }

    // TP22: Path.GetFileName с user input (если используется для записи)
    public IActionResult TP22_GetFileName(string userInput)
    {
        string fileName = Path.GetFileName(userInput);
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string fullPath = Path.Combine(_env.WebRootPath, "uploads", fileName);
        return PhysicalFile(fullPath, "application/octet-stream");
    }

    // TP23: User input через HttpRequest
    public async Task<IActionResult> TP23_FromHttpRequest()
    {
        string file = _request.Query["file"];
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, file);
        return PhysicalFile(path, "text/plain");
    }

    // TP24: User input из формы
    [HttpPost]
    public IActionResult TP24_FromForm(string documentName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = $@"{_env.WebRootPath}\docs\{documentName}";
        return PhysicalFile(path, "application/pdf");
    }

    // TP25: User input через Route
    [HttpGet("files/{fileName}")]
    public IActionResult TP25_FromRoute(string fileName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "downloads", fileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // TP26: User input с попыткой обхода через UrlDecode
    public IActionResult TP26_UrlDecodedPath(string encodedPath)
    {
        string decoded = Uri.UnescapeDataString(encodedPath);
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string fullPath = Path.Combine(_env.WebRootPath, decoded);
        return PhysicalFile(fullPath, "text/plain");
    }

    // TP27: User input через Base64 decode
    public IActionResult TP27_Base64Path(string base64Path)
    {
        byte[] data = Convert.FromBase64String(base64Path);
        string decodedPath = System.Text.Encoding.UTF8.GetString(data);
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string fullPath = Path.Combine(_env.WebRootPath, decodedPath);
        return PhysicalFile(fullPath, "text/plain");
    }

    // TP28: Множественные операции с файлами
    public IActionResult TP28_MultipleFileOperations(string sourceDir, string destDir)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        var files = Directory.GetFiles(sourceDir);
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        foreach (var file in files)
        {
            string destFile = Path.Combine(destDir, Path.GetFileName(file));
            System.IO.File.Copy(file, destFile);
        }
        return Ok();
    }

    // TP29: Использование в using statement
    public IActionResult TP29_UsingStatement(string filePath)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        using (var reader = new StreamReader(filePath))
        {
            string content = reader.ReadToEnd();
            return Content(content);
        }
    }

    // TP30: Асинхронное чтение файла
    public async Task<IActionResult> TP30_AsyncRead(string fileName)
    {
        // ruleid: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, fileName);
        string content = await System.IO.File.ReadAllTextAsync(path);
        return Content(content);
    }

    // ---------- False Positive (rule should NOT trigger) ----------

    // FP1: Путь из конфигурации
    public IActionResult FP1_FromConfiguration()
    {
        string uploadPath = Configuration.GetValue<string>("UploadPath");
        // ok: csharp_path_traversal_Rule-PathTraversal
        var files = Directory.GetFiles(uploadPath);
        return Ok(files);
    }

    // FP2: Имя файла из перечисления
    public IActionResult FP2_FromEnum(FileType type)
    {
        string fileName = type == FileType.Document ? "doc.pdf" : "image.jpg";
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "files", fileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP3: Генерация GUID имени файла
    public IActionResult FP3_GuidFileName()
    {
        string fileName = Guid.NewGuid().ToString() + ".txt";
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "temp", fileName);
        return PhysicalFile(path, "text/plain");
    }

    // FP4: Использование Path.GetFileName для безопасного имени
    public IActionResult FP4_SafeFileName(string userInput)
    {
        string safeFileName = Path.GetFileName(userInput);
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "uploads", safeFileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP5: Проверка через Path.GetFullPath и StartsWith
    public IActionResult FP5_WithValidation(string fileName)
    {
        string baseDir = _env.WebRootPath;
        string fullPath = Path.GetFullPath(Path.Combine(baseDir, fileName));
        
        if (!fullPath.StartsWith(baseDir))
        {
            return BadRequest("Path traversal detected");
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        return PhysicalFile(fullPath, "text/plain");
    }

    // FP6: Whitelist проверка
    public IActionResult FP6_WhitelistValidation(string fileName)
    {
        string[] allowedFiles = { "report.pdf", "summary.docx", "data.xlsx" };
        
        if (!allowedFiles.Contains(fileName))
        {
            return BadRequest("File not allowed");
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "documents", fileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP7: Регулярное выражение для валидации
    public IActionResult FP7_RegexValidation(string fileName)
    {
        if (!Regex.IsMatch(fileName, @"^[a-zA-Z0-9_\-\.]+$"))
        {
            return BadRequest("Invalid file name");
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "uploads", fileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP8: Маппинг через Dictionary
    public IActionResult FP8_DictionaryMapping(string fileKey)
    {
        var fileMap = new Dictionary<string, string>
        {
            ["annual"] = "report_2024.pdf",
            ["quarterly"] = "q1_report.pdf",
            ["monthly"] = "monthly_data.xlsx"
        };
        
        if (!fileMap.TryGetValue(fileKey, out string fileName))
        {
            return NotFound();
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "reports", fileName);
        return PhysicalFile(path, "application/pdf");
    }

    // FP9: Использование switch для безопасного выбора
    public IActionResult FP9_SwitchSelection(string documentType)
    {
        string fileName;
        switch (documentType.ToLower())
        {
            case "invoice":
                fileName = "invoice_template.pdf";
                break;
            case "contract":
                fileName = "standard_contract.pdf";
                break;
            default:
                return BadRequest("Unknown document type");
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "templates", fileName);
        return PhysicalFile(path, "application/pdf");
    }

    // FP10: Временный файл с безопасным именем
    public IActionResult FP10_TempFile()
    {
        string tempFile = Path.GetTempFileName();
        // ok: csharp_path_traversal_Rule-PathTraversal
        System.IO.File.WriteAllText(tempFile, "test content");
        return Ok();
    }

    // FP11: Path.Combine с константами
    public IActionResult FP11_ConstantPath()
    {
        string path = Path.Combine(_env.WebRootPath, "static", "images", "logo.png");
        // ok: csharp_path_traversal_Rule-PathTraversal
        return PhysicalFile(path, "image/png");
    }

    // FP12: Использование Environment.GetFolderPath
    public IActionResult FP12_SystemPath()
    {
        string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string configPath = Path.Combine(appDataPath, "MyApp", "config.json");
        // ok: csharp_path_traversal_Rule-PathTraversal
        string content = System.IO.File.ReadAllText(configPath);
        return Content(content);
    }

    // FP13: Путь из безопасного источника (JWT claim)
    public IActionResult FP13_FromJWT(string userId)
    {
        // Предполагаем, что userId из валидного JWT токена
        string userFolder = Path.Combine(_env.WebRootPath, "users", userId);
        // ok: csharp_path_traversal_Rule-PathTraversal
        if (Directory.Exists(userFolder))
        {
            return Ok(Directory.GetFiles(userFolder));
        }
        return NotFound();
    }

    // FP14: Использование Path.HasExtension для проверки
    public IActionResult FP14_ExtensionCheck(string fileName)
    {
        if (!Path.HasExtension(fileName))
        {
            return BadRequest("File must have extension");
        }
        
        string extension = Path.GetExtension(fileName);
        if (extension != ".pdf" && extension != ".docx")
        {
            return BadRequest("Invalid file type");
        }
        
        string safeName = Path.GetFileName(fileName);
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "documents", safeName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP15: Безопасное имя через Replace опасных символов
    public IActionResult FP15_SanitizeFileName(string userInput)
    {
        char[] invalidChars = Path.GetInvalidFileNameChars();
        string safeFileName = string.Join("_", userInput.Split(invalidChars));
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(_env.WebRootPath, "uploads", safeFileName);
        return PhysicalFile(path, "application/octet-stream");
    }

    // FP16: Использование относительных путей без доступа к корню
    public IActionResult FP16_RelativePath(string fileName)
    {
        string relativePath = Path.Combine("data", fileName);
        // Это все еще опасно, если fileName содержит ".."
        // Но если fileName проверен, то может быть безопасно
        
        if (fileName.Contains("..") || fileName.Contains("/") || fileName.Contains("\\"))
        {
            return BadRequest();
        }
        
        // ok: csharp_path_traversal_Rule-PathTraversal
        string path = Path.Combine(Directory.GetCurrentDirectory(), relativePath);
        return PhysicalFile(path, "text/plain");
    }
}

public enum FileType
{
    Document,
    Image,
    Video
}