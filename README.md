# 🔒 Security Rules for Semgrep

A curated, production-ready collection of static analysis security rules for [Semgrep](https://semgrep.dev/). Designed to help developers, security engineers, and DevOps teams detect vulnerabilities, enforce secure coding practices, and comply with industry standards (OWASP, CWE, MITRE) across multiple programming languages.


## 📊 Supported Languages & Rule Statistics

Statistics are based on `.yml` / `.yaml` rule definitions currently in the repository:

| Language       | Rules Count | Primary Coverage                          |
|----------------|-------------|-------------------------------------------|
| **Scala**      | `95`        | Web frameworks, XML/XXE, Injection, Crypto|
| **Python**     | `65`        | Django/Flask, Cryptography, Deserialization, OS exec |
| **Java**       | `56`        | Spring/Jakarta, SQLi, XXE, Auth, Crypto   |
| **C#**         | `31`        | ASP.NET, EF Core, Cookies, Injection      |
| **Dart**       | `27`        | Flutter security, Mobile, FFI, Obfuscation|
| **Go**         | `25`        | HTTP, Filesystem, TLS, Subprocess, Memory |
| **C/C++**      | `20`        | Memory safety, Buffer overflow, Race cond.|
| **JavaScript** | `10`        | Node.js, React, Eval, Timing attacks      |
| **TOTAL**      | **`320`**   |                                           |

> 💡 *Each rule includes a YAML definition and corresponding example/test files (`.cs`, `.py`, `.java`, etc.) to validate detection accuracy.*

## 🚀 Quick Start

### Prerequisites
```bash
pip install semgrep
# or
brew install semgrep
```



# 🔒 Правила безопасности для Semgrep

Коллекция готовых к продакшену правил статического анализа для [Semgrep](https://semgrep.dev/). Создана, чтобы помогать разработчикам, специалистам по безопасности и DevOps-инженерам выявлять уязвимости, внедрять безопасные практики кодирования и соответствовать отраслевым стандартам (OWASP, CWE, MITRE) на множестве языков программирования.


## 📊 Поддерживаемые языки и статистика правил

Статистика основана на `.yml` / `.yaml` файлах правил, представленных в репозитории:

| Язык           | Кол-во правил | Основное покрытие                             |
|----------------|---------------|-----------------------------------------------|
| **Scala**      | `95`          | Веб-фреймворки, XML/XXE, инъекции, криптография |
| **Python**     | `65`          | Django/Flask, криптография, десериализация, exec |
| **Java**       | `56`          | Spring/Jakarta, SQLi, XXE, аутентификация, крипто |
| **C#**         | `31`          | ASP.NET, EF Core, cookies, инъекции           |
| **Dart**       | `27`          | Flutter, мобильная безопасность, FFI, обфускация |
| **Go**         | `25`          | HTTP, файловая система, TLS, подпроцессы, память |
| **C/C++**      | `20`          | Безопасность памяти, переполнение буфера, гонки |
| **JavaScript** | `10`          | Node.js, React, eval, атаки по времени        |
| **ВСЕГО**      | **`320`**     |                                               |

> 💡 *Каждое правило состоит из YAML-описания и соответствующих примеров/тестов (`.cs`, `.py`, `.java` и др.) для валидации точности срабатываний.*

## 🚀 Быстрый старт

### Требования
```bash
pip install semgrep
# или
brew install semgrep
```