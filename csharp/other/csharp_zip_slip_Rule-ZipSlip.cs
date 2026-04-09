using System;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using ICSharpCode.SharpZipLib.Zip;
using ICSharpCode.SharpZipLib.Core;
using DotNetZip;
using System.Text;
using System.Linq;

namespace ZipSlipTestCases
{
    public class ZipSlipController : Controller
    {
        private readonly IWebHostEnvironment _env;
        private readonly string _uploadPath;

        public ZipSlipController(IWebHostEnvironment env)
        {
            _env = env;
            _uploadPath = Path.Combine(_env.WebRootPath, "uploads");
        }

        // ---------- True Positive (rule should trigger) ----------

        // TP1: ZipFile.ExtractToDirectory с user input (наиболее уязвимый)
        public IActionResult TP1_ZipFileExtract(string zipFileName)
        {
            string zipPath = Path.Combine(_uploadPath, zipFileName);
            string extractPath = Path.Combine(_uploadPath, "extracted");
            
            // ruleid: csharp_zip_slip_Rule-ZipSlip
            ZipFile.ExtractToDirectory(zipPath, extractPath);
            
            return Ok();
        }

        // TP2: ZipArchive.ExtractToDirectory (без проверки)
        public IActionResult TP2_ZipArchiveExtract(string zipFilePath)
        {
            string extractPath = Path.Combine(_uploadPath, "temp");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFilePath))
            {
                // ruleid: csharp_zip_slip_Rule-ZipSlip
                archive.ExtractToDirectory(extractPath);
            }
            
            return Ok();
        }

        // TP3: Ручное извлечение через ZipArchiveEntry (без проверки)
        public IActionResult TP3_ManualExtract(string zipPath)
        {
            string extractDir = Path.Combine(_uploadPath, "manual");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destinationPath = Path.Combine(extractDir, entry.FullName);
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destinationPath, overwrite: true);
                }
            }
            
            return Ok();
        }

        // TP4: SharpZipLib - FastZip.ExtractZip
        public IActionResult TP4_SharpZipLibFastZip(string zipFile)
        {
            string targetDir = Path.Combine(_uploadPath, "sharp_extract");
            
            var fastZip = new FastZip();
            // ruleid: csharp_zip_slip_Rule-ZipSlip
            fastZip.ExtractZip(zipFile, targetDir, null);
            
            return Ok();
        }

        // TP5: SharpZipLib - ZipFile.ExtractZip
        public IActionResult TP5_SharpZipLibExtractZip(string zipPath)
        {
            string outputDir = Path.Combine(_uploadPath, "sharp_output");
            
            using (var zipFile = new ICSharpCode.SharpZipLib.Zip.ZipFile(zipPath))
            {
                // ruleid: csharp_zip_slip_Rule-ZipSlip
                zipFile.ExtractZip(outputDir, null);
            }
            
            return Ok();
        }

        // TP6: SharpZipLib - ручное извлечение без проверки
        public IActionResult TP6_SharpZipLibManual(string zipFilePath)
        {
            string extractPath = Path.Combine(_uploadPath, "sharp_manual");
            
            using (var zipFile = new ICSharpCode.SharpZipLib.Zip.ZipFile(zipFilePath))
            {
                foreach (ZipEntry entry in zipFile)
                {
                    if (!entry.IsFile) continue;
                    
                    string entryFileName = entry.Name;
                    string fullZipToPath = Path.Combine(extractPath, entryFileName);
                    
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    using (var stream = zipFile.GetInputStream(entry))
                    using (var fs = new FileStream(fullZipToPath, FileMode.Create))
                    {
                        stream.CopyTo(fs);
                    }
                }
            }
            
            return Ok();
        }

        // TP7: DotNetZip - ZipFile.Extract
        public IActionResult TP7_DotNetZipExtract(string zipFileName)
        {
            string extractDir = Path.Combine(_uploadPath, "dotnetzip_extract");
            
            using (var zip = new Ionic.Zip.ZipFile(zipFileName))
            {
                // ruleid: csharp_zip_slip_Rule-ZipSlip
                zip.ExtractAll(extractDir);
            }
            
            return Ok();
        }

        // TP8: DotNetZip - ручное извлечение без проверки
        public IActionResult TP8_DotNetZipManual(string zipPath)
        {
            string outputDir = Path.Combine(_uploadPath, "dotnetzip_manual");
            
            using (var zip = new Ionic.Zip.ZipFile(zipPath))
            {
                foreach (var entry in zip.Entries)
                {
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.Extract(outputDir);
                }
            }
            
            return Ok();
        }

        // TP9: Path traversal через ZipEntry (../../etc/passwd)
        public IActionResult TP9_PathTraversalInZip(string zipPath)
        {
            string extractDir = Path.Combine(_uploadPath, "extract");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destinationPath = Path.GetFullPath(Path.Combine(extractDir, entry.FullName));
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destinationPath, true);
                }
            }
            
            return Ok();
        }

        // TP10: Неполная проверка - только начало пути
        public IActionResult TP10_IncompleteValidation(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "incomplete_extract");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destPath = Path.Combine(extractDir, entry.FullName);
                    // Проверяем только начало пути - недостаточно!
                    if (destPath.StartsWith(extractDir))
                    {
                        // ruleid: csharp_zip_slip_Rule-ZipSlip
                        entry.ExtractToFile(destPath, true);
                    }
                }
            }
            
            return Ok();
        }

        // TP11: Проверка через Path.GetFullPath после Combine (все еще опасно)
        public IActionResult TP11_GetFullPathAfterCombine(string zipPath)
        {
            string targetDir = Path.Combine(_uploadPath, "fullpath_extract");
            Directory.CreateDirectory(targetDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string fullPath = Path.GetFullPath(Path.Combine(targetDir, entry.FullName));
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(fullPath, true);
                }
            }
            
            return Ok();
        }

        // TP12: Удаление только одного типа разделителя
        public IActionResult TP12_RemoveOnlyBackslashes(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "remove_backslash_extract");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string safeName = entry.FullName.Replace("\\", "");
                    string destPath = Path.Combine(extractDir, safeName);
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destPath, true);
                }
            }
            
            return Ok();
        }

        // TP13: Replace ".." но можно обойти (например, ".../")
        public IActionResult TP13_WeakReplace(string zipPath)
        {
            string extractDir = Path.Combine(_uploadPath, "weak_replace_extract");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string safeName = entry.FullName.Replace("..", "");
                    string destPath = Path.Combine(extractDir, safeName);
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destPath, true);
                }
            }
            
            return Ok();
        }

        // TP14: Асинхронное извлечение без проверки
        public async Task<IActionResult> TP14_AsyncExtract(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "async_extract");
            
            await Task.Run(() =>
            {
                using (ZipArchive archive = ZipFile.OpenRead(zipFile))
                {
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    archive.ExtractToDirectory(extractDir);
                }
            });
            
            return Ok();
        }

        // TP15: Извлечение с перезаписью существующих файлов
        public IActionResult TP15_ExtractWithOverwrite(string zipPath)
        {
            string outputDir = Path.Combine(_uploadPath, "overwrite_extract");
            Directory.CreateDirectory(outputDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string targetPath = Path.Combine(outputDir, entry.FullName);
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(targetPath, overwrite: true);
                }
            }
            
            return Ok();
        }

        // TP16: Извлечение в поддиректорию с user input
        public IActionResult TP16_ExtractToUserDirectory(string zipFile, string subDir)
        {
            string extractPath = Path.Combine(_uploadPath, subDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                // ruleid: csharp_zip_slip_Rule-ZipSlip
                archive.ExtractToDirectory(extractPath);
            }
            
            return Ok();
        }

        // TP17: SharpZipLib с Path traversal
        public IActionResult TP17_SharpZipLibPathTraversal(string zipFilePath)
        {
            string extractPath = Path.Combine(_uploadPath, "sharp_slip");
            
            using (var zipFile = new ICSharpCode.SharpZipLib.Zip.ZipFile(zipFilePath))
            {
                foreach (ZipEntry entry in zipFile)
                {
                    if (entry.IsFile)
                    {
                        string fullPath = Path.Combine(extractPath, entry.Name);
                        // ruleid: csharp_zip_slip_Rule-ZipSlip
                        using (var stream = zipFile.GetInputStream(entry))
                        using (var fs = new FileStream(fullPath, FileMode.Create))
                        {
                            stream.CopyTo(fs);
                        }
                    }
                }
            }
            
            return Ok();
        }

        // TP18: DotNetZip с path traversal
        public IActionResult TP18_DotNetZipPathTraversal(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "dotnetzip_slip");
            
            using (var zip = new Ionic.Zip.ZipFile(zipFile))
            {
                foreach (var entry in zip.Entries)
                {
                    // ruleid: csharp_zip_slip_Rule-ZipSlip
                    entry.Extract(extractDir, ExtractExistingFileAction.OverwriteSilently);
                }
            }
            
            return Ok();
        }

        // TP19: Извлечение через MemoryStream (без проверки)
        public IActionResult TP19_MemoryStreamExtract(byte[] zipData)
        {
            string extractDir = Path.Combine(_uploadPath, "memory_extract");
            
            using (var stream = new MemoryStream(zipData))
            using (ZipArchive archive = new ZipArchive(stream))
            {
                // ruleid: csharp_zip_slip_Rule-ZipSlip
                archive.ExtractToDirectory(extractDir);
            }
            
            return Ok();
        }

        // TP20: Извлечение с изменением имени файла (но не пути)
        public IActionResult TP20_ExtractWithNameChange(string zipFile)
        {
            string outputDir = Path.Combine(_uploadPath, "name_change");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string fileName = Path.GetFileName(entry.FullName);
                    string destPath = Path.Combine(outputDir, fileName);
                    // ruleid: csharp_zip_slip_Rule-ZipSlip - все еще опасно из-за директорий
                    entry.ExtractToFile(destPath, true);
                }
            }
            
            return Ok();
        }

        // ---------- False Positive (rule should NOT trigger) ----------

        // FP1: Правильная валидация через GetFullPath
        public IActionResult FP1_SafeExtractWithValidation(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "safe_extract");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destinationPath = Path.GetFullPath(Path.Combine(extractDir, entry.FullName));
                    
                    // Правильная проверка: убеждаемся, что путь внутри целевой директории
                    if (!destinationPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        continue; // Пропускаем zip slip попытку
                    }
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destinationPath, true);
                }
            }
            
            return Ok();
        }

        // FP2: Проверка через NormalizePath
        public IActionResult FP2_SafeExtractWithNormalization(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "normalized_extract");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string normalizedPath = Path.GetFullPath(entry.FullName).Replace('/', '\\');
                    string destinationPath = Path.Combine(extractDir, normalizedPath);
                    string fullDestinationPath = Path.GetFullPath(destinationPath);
                    
                    if (!fullDestinationPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(fullDestinationPath, true);
                }
            }
            
            return Ok();
        }

        // FP3: Использование Path.GetFileName (только имя файла, без директорий)
        public IActionResult FP3_ExtractOnlyFileNames(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "only_files");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string fileName = Path.GetFileName(entry.FullName);
                    if (string.IsNullOrEmpty(fileName)) continue;
                    
                    string destinationPath = Path.Combine(extractDir, fileName);
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(destinationPath, true);
                }
            }
            
            return Ok();
        }

        // FP4: Создание поддиректорий с проверкой
        public IActionResult FP4_SafeCreateSubdirectories(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "safe_dirs");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destinationPath = Path.Combine(extractDir, entry.FullName);
                    string fullPath = Path.GetFullPath(destinationPath);
                    
                    if (!fullPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("Zip slip detected");
                    }
                    
                    if (entry.Name == "")
                    {
                        Directory.CreateDirectory(fullPath);
                    }
                    else
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(fullPath));
                        // ok: csharp_zip_slip_Rule-ZipSlip
                        entry.ExtractToFile(fullPath, true);
                    }
                }
            }
            
            return Ok();
        }

        // FP5: SharpZipLib с проверкой
        public IActionResult FP5_SharpZipLibSafe(string zipFilePath)
        {
            string extractPath = Path.Combine(_uploadPath, "sharp_safe");
            
            using (var zipFile = new ICSharpCode.SharpZipLib.Zip.ZipFile(zipFilePath))
            {
                foreach (ZipEntry entry in zipFile)
                {
                    if (!entry.IsFile) continue;
                    
                    string entryFileName = entry.Name;
                    string fullZipToPath = Path.Combine(extractPath, entryFileName);
                    string fullPath = Path.GetFullPath(fullZipToPath);
                    
                    if (!fullPath.StartsWith(extractPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    
                    Directory.CreateDirectory(Path.GetDirectoryName(fullPath));
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    using (var stream = zipFile.GetInputStream(entry))
                    using (var fs = new FileStream(fullPath, FileMode.Create))
                    {
                        stream.CopyTo(fs);
                    }
                }
            }
            
            return Ok();
        }

        // FP6: DotNetZip с проверкой
        public IActionResult FP6_DotNetZipSafe(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "dotnetzip_safe");
            
            using (var zip = new Ionic.Zip.ZipFile(zipFile))
            {
                foreach (var entry in zip.Entries)
                {
                    string fullPath = Path.GetFullPath(Path.Combine(extractDir, entry.FileName));
                    
                    if (!fullPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.Extract(extractDir);
                }
            }
            
            return Ok();
        }

        // FP7: Извлечение только в память (без записи на диск)
        public IActionResult FP7_ExtractToMemory(string zipFile)
        {
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    // ok: csharp_zip_slip_Rule-ZipSlip - нет записи на диск
                    using (var stream = entry.Open())
                    using (var ms = new MemoryStream())
                    {
                        stream.CopyTo(ms);
                        byte[] content = ms.ToArray();
                        // Обработка в памяти
                    }
                }
            }
            
            return Ok();
        }

        // FP8: Проверка имени entry через whitelist
        public IActionResult FP8_WhitelistValidation(string zipFile)
        {
            string[] allowedEntries = { "config.json", "data.xml", "images/logo.png" };
            string extractDir = Path.Combine(_uploadPath, "whitelist_extract");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (!allowedEntries.Contains(entry.FullName))
                    {
                        continue;
                    }
                    
                    string destPath = Path.Combine(extractDir, entry.FullName);
                    string fullPath = Path.GetFullPath(destPath);
                    
                    if (!fullPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(fullPath, true);
                }
            }
            
            return Ok();
        }

        // FP9: Извлечение только файлов без директорий
        public IActionResult FP9_FlattenExtract(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "flatten_extract");
            Directory.CreateDirectory(extractDir);
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                int counter = 0;
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (entry.Name == "") continue;
                    
                    string uniqueName = $"{counter}_{entry.Name}";
                    string destPath = Path.Combine(extractDir, uniqueName);
                    string fullPath = Path.GetFullPath(destPath);
                    
                    // ok: csharp_zip_slip_Rule-ZipSlip
                    entry.ExtractToFile(fullPath, true);
                    counter++;
                }
            }
            
            return Ok();
        }

        // FP10: Константный zip файл (не user input)
        public IActionResult FP10_ConstantZipFile()
        {
            string zipPath = Path.Combine(_env.ContentRootPath, "Resources", "template.zip");
            string extractDir = Path.Combine(_uploadPath, "template_extract");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                // ok: csharp_zip_slip_Rule-ZipSlip - zip файл не из user input
                archive.ExtractToDirectory(extractDir);
            }
            
            return Ok();
        }

        // FP11: Извлечение с проверкой через рекурсивное создание
        public IActionResult FP11_RecursiveSafeExtract(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "recursive_safe");
            
            using (ZipArchive archive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destPath = Path.Combine(extractDir, entry.FullName);
                    string fullDestPath = Path.GetFullPath(destPath);
                    
                    if (!fullDestPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new Exception("Invalid entry");
                    }
                    
                    if (string.IsNullOrEmpty(entry.Name))
                    {
                        Directory.CreateDirectory(fullDestPath);
                    }
                    else
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(fullDestPath));
                        // ok: csharp_zip_slip_Rule-ZipSlip
                        entry.ExtractToFile(fullDestPath, true);
                    }
                }
            }
            
            return Ok();
        }

        // FP12: Использование сторонней безопасной библиотеки
        public IActionResult FP12_SafeZipLibrary(string zipFile)
        {
            string extractDir = Path.Combine(_uploadPath, "safe_lib_extract");
            
            // Используем библиотеку с защитой от Zip Slip
            var extractor = new SafeZipExtractor();
            // ok: csharp_zip_slip_Rule-ZipSlip
            extractor.ExtractSafely(zipFile, extractDir);
            
            return Ok();
        }
    }
    
    // Вспомогательный класс для безопасного извлечения
    public class SafeZipExtractor
    {
        public void ExtractSafely(string zipPath, string extractDir)
        {
            using (ZipArchive archive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    string destPath = Path.GetFullPath(Path.Combine(extractDir, entry.FullName));
                    if (!destPath.StartsWith(extractDir, StringComparison.OrdinalIgnoreCase))
                        continue;
                    
                    if (string.IsNullOrEmpty(entry.Name))
                        Directory.CreateDirectory(destPath);
                    else
                        entry.ExtractToFile(destPath, true);
                }
            }
        }
    }
}