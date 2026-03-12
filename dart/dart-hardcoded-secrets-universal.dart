// test_dart_secrets.dart
// Тестовый файл для проверки правила dart-hardcoded-secrets-universal
// Исправлена версия: v1.1 (убран невалидный синтаксис Dart)

import 'package:flutter/material.dart';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ (должны быть найдены правилом)
// =============================================================================

// --- Тест 1: Прямое присваивание переменной с ключевым словом ---
// ruleid: dart-hardcoded-secrets-universal
final String apiKey = "sk_live_51HxYz2K3LmNpQrStUvWxYz";

// ruleid: dart-hardcoded-secrets-universal
const String secretToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ruleid: dart-hardcoded-secrets-universal
var password = "SuperSecretPassword123!";

// ruleid: dart-hardcoded-secrets-universal
String authCredential = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

// --- Тест 2: Const и Final вариации ---
// ruleid: dart-hardcoded-secrets-universal
final api_key = "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ruleid: dart-hardcoded-secrets-universal
const PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----MIIEpA";

// --- Тест 3: String.fromEnvironment с defaultValue (критично для Flutter) ---
// ruleid: dart-hardcoded-secrets-universal
String token = String.fromEnvironment('API_TOKEN', defaultValue: 'hardcoded_fallback_secret_123');

// ruleid: dart-hardcoded-secrets-universal
String stripeKey = String.fromEnvironment('STRIPE_KEY', defaultValue: 'sk_test_4eC39HqLyjWDarjtT1zdp7dc');

// --- Тест 4: Секреты в Map/JSON конфигурации ---
// ruleid: dart-hardcoded-secrets-universal
var config = {
  'api_key': 'AKIAIOSFODNN7EXAMPLE',
  'endpoint': 'https://api.example.com'
};

// ruleid: dart-hardcoded-secrets-universal
Map<String, String> secrets = {'password': 'AdminPass123456'};

// ruleid: dart-hardcoded-secrets-universal
final credentials = {"auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"};

// --- Тест 5: Разные названия переменных (AWS, Firebase, Stripe) ---
// ruleid: dart-hardcoded-secrets-universal
String awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// ruleid: dart-hardcoded-secrets-universal
final firebaseApiKey = "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ruleid: dart-hardcoded-secrets-universal
const stripeSecretKey = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx";

// --- Тест 6: Регистронезависимость ---
// ruleid: dart-hardcoded-secrets-universal
String API_KEY = "test_api_key_value_1234567890";

// ruleid: dart-hardcoded-secrets-universal
final AuthToken = "token_value_1234567890abcdef";

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ (НЕ должны быть найдены - защита от False Positives)
// =============================================================================

// --- Тест 7: Плейсхолдеры и заглушки ---
// ok: dart-hardcoded-secrets-universal
final String apiKey = "YOUR_API_KEY_HERE";

// ok: dart-hardcoded-secrets-universal
const String token = "xxx";

// ok: dart-hardcoded-secrets-universal
var secret = "CHANGE_ME";

// ok: dart-hardcoded-secrets-universal
String password = "INSERT_PASSWORD_HERE";

// ok: dart-hardcoded-secrets-universal
final auth = "EXAMPLE_KEY";

// ok: dart-hardcoded-secrets-universal
const credential = "test_value";

// ok: dart-hardcoded-secrets-universal
String key = "demo_key";

// ok: dart-hardcoded-secrets-universal
var token = "null";

// ok: dart-hardcoded-secrets-universal
final secret = "empty";

// --- Тест 8: Безопасные имена переменных (не триггерят правило) ---
// ok: dart-hardcoded-secrets-universal
String url = "https://api.example.com/v1";

// ok: dart-hardcoded-secrets-universal
final message = "Hello World";

// ok: dart-hardcoded-secrets-universal
const String title = "My Application";

// ok: dart-hardcoded-secrets-universal
var description = "This is a description";

// --- Тест 9: Короткие значения (меньше 10 символов) ---
// ok: dart-hardcoded-secrets-universal
final pass = "12345";

// ok: dart-hardcoded-secrets-universal
String key = "short";

// ok: dart-hardcoded-secrets-universal
const token = "abc";

// --- Тест 10: Безопасный String.fromEnvironment (без defaultValue) ---
// ok: dart-hardcoded-secrets-universal
String safeToken = String.fromEnvironment('API_TOKEN');

// ok: dart-hardcoded-secrets-universal
final apiKey = String.fromEnvironment('API_KEY', defaultValue: '');

// --- Тест 11: Публичные идентификаторы (не секреты) ---
// ok: dart-hardcoded-secrets-universal
final String appId = "com.example.myapp";

// ok: dart-hardcoded-secrets-universal
const String packageName = "io.flutter.app";

// ok: dart-hardcoded-secrets-universal
String bundleId = "org.dartlang.flutter";

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ (Edge Cases) - ИСПРАВЛЕНО
// =============================================================================

// --- Тест 12: Секрет в середине строки (должен ловиться) ---
// ruleid: dart-hardcoded-secrets-universal
final config = {"api-key-prod": "prod_secret_key_1234567890"};

// --- Тест 13: Подчеркивания в имени переменной (Валидный Dart) ---
// ИСПРАВЛЕНО: было auth-token (ошибка синтаксиса), стало auth_token
// ruleid: dart-hardcoded-secrets-universal
String api_key_prod = "production_api_key_1234567890";

// ruleid: dart-hardcoded-secrets-universal
final auth_token = "bearer_token_1234567890abcdef";

// --- Тест 14: Секрет в многозначной карте ---
// ruleid: dart-hardcoded-secrets-universal
var multiConfig = {
  'host': 'api.example.com',
  'port': 443,
  'secret': 'very_secret_value_1234567890',
  'timeout': 30
};

// --- Тест 15: CamelCase и snake_case комбинации ---
// ruleid: dart-hardcoded-secrets-universal
String apiKeyProduction = "prod_key_1234567890abcdefghij";

// ruleid: dart-hardcoded-secrets-universal
final stripe_api_key = "sk_live_1234567890abcdefghij";

// =============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ
// =============================================================================

class ApiService {
  // ruleid: dart-hardcoded-secrets-universal
  static const String _apiKey = "internal_api_key_1234567890";
  
  // ok: dart-hardcoded-secrets-universal
  static const String _placeholder = "YOUR_KEY_HERE";
  
  // ok: dart-hardcoded-secrets-universal
  String baseUrl = "https://api.example.com";
  
  // ruleid: dart-hardcoded-secrets-universal
  final String _authToken = "x_auth_token_1234567890abcdef";
  
  void authenticate() {
    // ok: dart-hardcoded-secrets-universal
    print("Authenticating...");
    
    // ruleid: dart-hardcoded-secrets-universal
    String localSecret = "local_secret_1234567890";
  }
}

// ok: dart-hardcoded-secrets-universal
const String version = "1.0.0";

// ok: dart-hardcoded-secrets-universal
final buildNumber = 123;

// ruleid: dart-hardcoded-secrets-universal
Map<String, dynamic> env = {
  "secret_key": "env_secret_1234567890abcdef",
  "debug": true
};