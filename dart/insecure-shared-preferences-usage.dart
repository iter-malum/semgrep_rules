// test_insecure_storage.dart
// Тестовый файл для проверки правила: insecure-shared-preferences-usage
// Покрытие: позитивные и негативные кейсы, граничные случаи, паттерны обхода

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ И ПЕРЕМЕННЫЕ
// =============================================================================

// ok: insecure-shared-preferences-usage
const String APP_THEME_KEY = 'app_theme';

// ok: insecure-shared-preferences-usage
const String LANGUAGE_CODE = 'language_code';

// ok: insecure-shared-preferences-usage
const String ONBOARDING_COMPLETED = 'onboarding_completed';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SharedPreferences с чувствительными данными
// =============================================================================

// -----------------------------------------------------------------------------
// Группа 1: setString с явными чувствительными ключами
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveAuthToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> savePassword() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('password', 'SuperSecretP@ssw0rd123');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveApiKey() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('api_key', 'sk_live_51HxYz2K3LmNpQrStUvWxYz');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveSecret() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('secret', 'my_super_secret_value_12345');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveAccessToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('access_token', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveRefreshToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('refresh_token', 'dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> savePrivateKey() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('private_key', '-----BEGIN RSA PRIVATE KEY-----...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveCredential() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('credential', 'user:password123');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveBearerToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('bearer_token', 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveStripeKey() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('stripe_key', 'sk_test_4eC39HqLyjWDarjtT1zdp7dc');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveFirebaseToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('firebase_token', 'AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveAwsSecret() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('aws_secret_access_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
}

// -----------------------------------------------------------------------------
// Группа 2: setString с вариациями имён ключей (регистр, подчёркивания, дефисы)
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveTokenVariations() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('AuthToken', 'token1');
  await prefs.setString('AUTH_TOKEN', 'token2');
  await prefs.setString('auth-token', 'token3');
  await prefs.setString('authToken', 'token4');
  await prefs.setString('user_auth_token', 'token5');
}

// ruleid: insecure-shared-preferences-usage
Future<void> savePasswordVariations() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('Password', 'pass1');
  await prefs.setString('USER_PASSWORD', 'pass2');
  await prefs.setString('user-password', 'pass3');
  await prefs.setString('dbPassword', 'pass4');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveApiKeyVariations() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('APIKey', 'key1');
  await prefs.setString('API_KEY', 'key2');
  await prefs.setString('api-key', 'key3');
  await prefs.setString('backend_api_key', 'key4');
}

// -----------------------------------------------------------------------------
// Группа 3: Другие типы данных SharedPreferences с чувствительными ключами
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveSensitiveInt() async {
  final prefs = await SharedPreferences.getInstance();
  // PIN-код, секретный код доступа
  await prefs.setInt('security_pin', 1234);
  await prefs.setInt('access_code', 9876);
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveSensitiveBool() async {
  final prefs = await SharedPreferences.getInstance();
  // Флаги, указывающие на наличие чувствительных данных
  await prefs.setBool('is_authenticated', true);
  await prefs.setBool('has_valid_token', true);
  await prefs.setBool('password_saved', true);
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveSensitiveDouble() async {
  final prefs = await SharedPreferences.getInstance();
  // Например, баланс или кредитные данные (хотя это спорно)
  await prefs.setDouble('wallet_balance', 1234.56);
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveSensitiveStringList() async {
  final prefs = await SharedPreferences.getInstance();
  // Список токенов или ключей
  await prefs.setStringList('backup_tokens', ['token1', 'token2', 'token3']);
  await prefs.setStringList('api_keys', ['key1', 'key2']);
}

// -----------------------------------------------------------------------------
// Группа 4: Разные способы получения экземпляра SharedPreferences
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveWithDefaultInstance() async {
  final prefs = SharedPreferences.getInstance();
  await prefs.then((p) => p.setString('auth_token', 'secret'));
}

// ruleid: insecure-shared-preferences-usage
void saveWithCallback() {
  SharedPreferences.getInstance().then((prefs) {
    prefs.setString('password', 'secret123');
  });
}

// ruleid: insecure-shared-preferences-usage
class TokenManager {
  Future<void> saveToken(String token) async {
    // ruleid: insecure-shared-preferences-usage
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('user_token', token);
  }
}

// -----------------------------------------------------------------------------
// Группа 5: Чувствительные данные в картах/объектах, сохраняемых через SharedPreferences
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveUserDataMap() async {
  final prefs = await SharedPreferences.getInstance();
  final userData = {
    'username': 'admin',
    'password': 'admin123', // чувствительное поле внутри объекта
    'email': 'admin@example.com'
  };
  // Сохраняем как JSON строку - пароль внутри!
  await prefs.setString('user_data', '{"password":"admin123"}');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveConfigWithSecret() async {
  final prefs = await SharedPreferences.getInstance();
  // Конфигурация содержит секретный ключ
  await prefs.setString('app_config', '{"api_key":"sk_live_abc123","debug":false}');
}

// -----------------------------------------------------------------------------
// Группа 6: Динамические ключи с чувствительными суффиксами/префиксами
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveWithDynamicKey(String userId) async {
  final prefs = await SharedPreferences.getInstance();
  // Ключ формируется динамически, но содержит чувствительное слово
  await prefs.setString('${userId}_auth_token', 'secret_token_value');
  await prefs.setString('user_${userId}_password', 'user_password');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveWithConcatenatedKey() async {
  final prefs = await SharedPreferences.getInstance();
  final prefix = 'prod';
  // ruleid: insecure-shared-preferences-usage (ключ содержит "api_key")
  await prefs.setString('${prefix}_api_key', 'secret_key_value');
}

// -----------------------------------------------------------------------------
// Группа 7: Приватные методы и переменные класса
// -----------------------------------------------------------------------------

class SecureStorageAntiPattern {
  // ruleid: insecure-shared-preferences-usage
  Future<void> _saveInternalToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('_internal_auth_token', token);
  }

  // ruleid: insecure-shared-preferences-usage
  static Future<void> saveStaticCredential(String cred) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('static_credential', cred);
  }
}

// -----------------------------------------------------------------------------
// Группа 8: Обёртки и сервисные классы (распространённый анти-паттерн)
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
class AuthService {
  static const String _prefsKey = 'auth_token';
  
  Future<void> login(String token) async {
    final prefs = await SharedPreferences.getInstance();
    // Даже если ключ в константе - это всё равно небезопасно
    await prefs.setString(_prefsKey, token);
  }
}

// ruleid: insecure-shared-preferences-usage
class ApiClient {
  final String _apiKey;
  
  ApiClient(this._apiKey);
  
  Future<void> persistApiKey() async {
    final prefs = await SharedPreferences.getInstance();
    // Сохранение ключа, переданного в конструктор
    await prefs.setString('api_key', _apiKey);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование (НЕ должны триггерить правило)
// =============================================================================

// -----------------------------------------------------------------------------
// Группа 1: SharedPreferences с НЕ-чувствительными ключами
// -----------------------------------------------------------------------------

// ok: insecure-shared-preferences-usage
Future<void> saveThemePreference() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('theme', 'dark');
}

// ok: insecure-shared-preferences-usage
Future<void> saveLanguagePreference() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('language', 'ru');
}

// ok: insecure-shared-preferences-usage
Future<void> saveOnboardingStatus() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setBool('onboarding_completed', true);
}

// ok: insecure-shared-preferences-usage
Future<void> saveAppSettings() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('font_size', '14');
  await prefs.setBool('notifications_enabled', true);
  await prefs.setString('home_screen_layout', 'grid');
}

// ok: insecure-shared-preferences-usage
Future<void> saveUserPreferences() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('username_display', 'JohnDoe');
  await prefs.setString('avatar_url', 'https://example.com/avatar.png');
  await prefs.setBool('is_premium_user', false);
}

// ok: insecure-shared-preferences-usage
Future<void> saveCacheMetadata() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('last_cache_update', '2024-01-15T10:30:00Z');
  await prefs.setInt('cache_version', 3);
}

// -----------------------------------------------------------------------------
// Группа 2: Использование flutter_secure_storage (правильный подход)
// -----------------------------------------------------------------------------

// ok: insecure-shared-preferences-usage
Future<void> saveTokenSecurely() async {
  const storage = FlutterSecureStorage();
  await storage.write(key: 'auth_token', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');
}

// ok: insecure-shared-preferences-usage
Future<void> savePasswordSecurely() async {
  const storage = FlutterSecureStorage();
  await storage.write(key: 'password', value: 'SuperSecretP@ssw0rd123');
}

// ok: insecure-shared-preferences-usage
class SecureAuthService {
  static const _storage = FlutterSecureStorage();
  
  Future<void> saveCredentials(String token, String refreshToken) async {
    await _storage.write(key: 'auth_token', value: token);
    await _storage.write(key: 'refresh_token', value: refreshToken);
  }
  
  Future<String?> getAuthToken() async {
    return await _storage.read(key: 'auth_token');
  }
}

// ok: insecure-shared-preferences-usage
Future<void> saveApiKeySecurely() async {
  const storage = FlutterSecureStorage();
  await storage.write(key: 'api_key', value: 'sk_live_51HxYz2K3LmNpQrStUvWxYz');
}

// -----------------------------------------------------------------------------
// Группа 3: Ключи, которые похожи на чувствительные, но таковыми не являются
// -----------------------------------------------------------------------------

// ok: insecure-shared-preferences-usage
Future<void> saveNonSensitiveWithTokenInName() async {
  final prefs = await SharedPreferences.getInstance();
  // "token" в контексте игровых жетонов, а не аутентификации
  await prefs.setInt('game_tokens', 150);
  await prefs.setString('token_display_name', 'Gold Token');
}

// ok: insecure-shared-preferences-usage
Future<void> saveNonSensitiveWithKeyInName() async {
  final prefs = await SharedPreferences.getInstance();
  // "key" в контексте клавиш или сортировки, а не API-ключа
  await prefs.setString('keyboard_layout', 'qwerty');
  await prefs.setString('sort_key', 'date_desc');
  await prefs.setBool('show_keys_hint', true);
}

// ok: insecure-shared-preferences-usage
Future<void> saveNonSensitiveWithSecretInName() async {
  final prefs = await SharedPreferences.getInstance();
  // "secret" в контексте игровых "секретов" или скрытых элементов
  await prefs.setBool('secret_level_unlocked', true);
  await prefs.setString('secret_character_skin', 'ninja');
}

// -----------------------------------------------------------------------------
// Группа 4: Закомментированный или задепрекейченный код
// -----------------------------------------------------------------------------

// Этот код закомментирован - не должен анализироваться
/*
Future<void> deprecatedSaveToken() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('auth_token', 'old_token');
}
*/

// ok: insecure-shared-preferences-usage
Future<void> migrateFromInsecureStorage() async {
  final prefs = await SharedPreferences.getInstance();
  const secureStorage = FlutterSecureStorage();
  
  // Миграция: читаем из небезопасного, пишем в безопасное, удаляем из небезопасного
  final oldToken = prefs.getString('auth_token');
  if (oldToken != null) {
    await secureStorage.write(key: 'auth_token', value: oldToken);
    await prefs.remove('auth_token'); // Удаляем после миграции
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ И EDGE CASES
// =============================================================================

// -----------------------------------------------------------------------------
// Edge Case 1: Ключи с экранированием и специальными символами
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveWithSpecialCharsInKey() async {
  final prefs = await SharedPreferences.getInstance();
  // Даже с спецсимволами ключ содержит чувствительное слово
  await prefs.setString('auth.token.v2', 'new_token_format');
  await prefs.setString('user:password', 'colon_separated');
  await prefs.setString('api/key/prod', 'production_key');
}

// -----------------------------------------------------------------------------
// Edge Case 2: Массивы и вложенные структуры
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveNestedSensitiveData() async {
  final prefs = await SharedPreferences.getInstance();
  // JSON с вложенными чувствительными данными
  final config = {
    'api': {
      'endpoint': 'https://api.example.com',
      'credentials': {
        'api_key': 'sk_live_secret',
        'token': 'bearer_token_value'
      }
    }
  };
  await prefs.setString('app_config', jsonEncode(config));
}

// -----------------------------------------------------------------------------
// Edge Case 3: Условное сохранение (зависит от флага)
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveConditionally(String token, bool rememberMe) async {
  final prefs = await SharedPreferences.getInstance();
  if (rememberMe) {
    // Условное сохранение токена - всё равно небезопасно
    await prefs.setString('auth_token', token);
  }
}

// -----------------------------------------------------------------------------
// Edge Case 4: Сохранение в цикле или при итерации
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveMultipleTokens(List<String> tokens) async {
  final prefs = await SharedPreferences.getInstance();
  for (int i = 0; i < tokens.length; i++) {
    // Динамические ключи с чувствительным суффиксом
    await prefs.setString('backup_token_$i', tokens[i]);
  }
}

// -----------------------------------------------------------------------------
// Edge Case 5: Extension methods на SharedPreferences
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
extension SecurePrefs on SharedPreferences {
  Future<bool> saveAuthToken(String token) {
    // Extension метод, который сохраняет токен небезопасно
    return setString('auth_token', token);
  }
}

// ok: insecure-shared-preferences-usage
extension SafePrefs on SharedPreferences {
  Future<bool> saveTheme(String theme) {
    // Extension метод для безопасных настроек
    return setString('theme', theme);
  }
}

// -----------------------------------------------------------------------------
// Edge Case 6: Mock-объекты и тестовый код
// -----------------------------------------------------------------------------

// ok: insecure-shared-preferences-usage (в тестовом файле это допустимо)
@visibleForTesting
Future<void> setupTestPreferences() async {
  final prefs = await SharedPreferences.getInstance();
  // В тестах можно использовать заглушки
  await prefs.setString('test_auth_token', 'fake_token_for_testing');
  await prefs.setString('test_api_key', 'fake_key_for_testing');
}

// -----------------------------------------------------------------------------
// Edge Case 7: Обработка ошибок и fallback-значения
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<String> getAuthTokenWithFallback() async {
  final prefs = await SharedPreferences.getInstance();
  final token = prefs.getString('auth_token');
  
  if (token == null) {
    // Fallback: сохраняем новый токен при отсутствии
    const newToken = 'default_fallback_token_12345';
    await prefs.setString('auth_token', newToken); // Небезопасно!
    return newToken;
  }
  return token;
}

// -----------------------------------------------------------------------------
// Edge Case 8: Шифрование перед сохранением (ложное чувство безопасности)
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> saveEncryptedToken(String plainToken) async {
  final prefs = await SharedPreferences.getInstance();
  // Даже если данные зашифрованы, SharedPreferences не предназначен для секретов
  // Шифрование должно быть на уровне flutter_secure_storage или специализированного хранилища
  final encrypted = _simpleEncrypt(plainToken);
  await prefs.setString('encrypted_auth_token', encrypted);
}

String _simpleEncrypt(String input) {
  // Упрощённое "шифрование" для примера (не использовать в продакшене!)
  return input.split('').reversed.join();
}

// =============================================================================
// КОМБИНИРОВАННЫЕ СЦЕНАРИИ
// =============================================================================

// -----------------------------------------------------------------------------
// Сценарий 1: Полная аутентификация с сохранением данных
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
class LoginService {
  Future<bool> login(String email, String password) async {
    // ... логика аутентификации ...
    final authToken = 'generated_token_abc123';
    final refreshToken = 'refresh_xyz789';
    
    final prefs = await SharedPreferences.getInstance();
    
    // ruleid: insecure-shared-preferences-usage (несколько нарушений в одном методе)
    await prefs.setString('auth_token', authToken);
    await prefs.setString('refresh_token', refreshToken);
    await prefs.setString('user_email', email); // ok: email не является секретом
    
    return true;
  }
}

// -----------------------------------------------------------------------------
// Сценарий 2: Конфигурация приложения с секретами
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> initializeAppConfig() async {
  final prefs = await SharedPreferences.getInstance();
  
  // Безопасные настройки
  await prefs.setString('app_version', '1.0.0');
  await prefs.setBool('analytics_enabled', true);
  
  // Небезопасные: секреты в конфиге
  await prefs.setString('config', jsonEncode({
    'api_base_url': 'https://api.example.com',
    'api_key': 'sk_live_production_key',
    'webhook_secret': 'whsec_xxxxxxxxxxxx'
  }));
}

// -----------------------------------------------------------------------------
// Сценарий 3: Кэширование ответов API с чувствительными данными
// -----------------------------------------------------------------------------

// ruleid: insecure-shared-preferences-usage
Future<void> cacheApiResponse(Map<String, dynamic> response) async {
  final prefs = await SharedPreferences.getInstance();
  
  // Если ответ содержит токены или ключи - кэширование небезопасно
  if (response.containsKey('access_token')) {
    await prefs.setString('cached_token', response['access_token']);
  }
  
  // Даже если кэшируем весь ответ как JSON
  await prefs.setString('api_response_cache', jsonEncode(response));
}

// =============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ПОЗИТИВНЫЕ ТЕСТЫ ДЛЯ ПОЛНОГО ПОКРЫТИЯ
// =============================================================================

// ruleid: insecure-shared-preferences-usage
Future<void> saveOAuthCredentials() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('oauth_access_token', 'ya29.a0AfH6SMB...');
  await prefs.setString('oauth_refresh_token', '1//0g...');
  await prefs.setString('oauth_id_token', 'eyJhbGciOiJSUzI1NiIs...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveDatabaseCredentials() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('db_password', 'db_super_secret_pass');
  await prefs.setString('db_connection_string', 'mongodb://user:pass@host/db');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveEncryptionKeys() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('encryption_key', 'aes_256_key_32_bytes_long!!');
  await prefs.setString('encryption_iv', '16_byte_iv_value');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveWebhookSecrets() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('stripe_webhook_secret', 'whsec_...');
  await prefs.setString('github_webhook_secret', 'ghwhsec_...');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveThirdPartyTokens() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('facebook_access_token', 'EAAB...');
  await prefs.setString('google_api_key', 'AIzaSy...');
  await prefs.setString('twitter_bearer_token', 'AAAAAAAAAAAAAAAAAAAA...');
}

// =============================================================================
// ДОПОЛНИТЕЛЬНЫЕ НЕГАТИВНЫЕ ТЕСТЫ
// =============================================================================

// ok: insecure-shared-preferences-usage
Future<void> saveAnalyticsData() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('analytics_session_id', 'sess_abc123');
  await prefs.setInt('analytics_event_count', 42);
}

// ok: insecure-shared-preferences-usage
Future<void> saveUIState() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setBool('sidebar_collapsed', true);
  await prefs.setString('active_tab', 'settings');
  await prefs.setDouble('scroll_position', 150.5);
}

// ok: insecure-shared-preferences-usage
Future<void> saveFeatureFlags() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setBool('feature_new_ui_enabled', true);
  await prefs.setBool('feature_beta_access', false);
  await prefs.setString('feature_rollout_percentage', '25');
}

// ok: insecure-shared-preferences-usage
Future<void> saveLocalData() async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setStringList('recent_searches', ['dart', 'flutter', 'semgrep']);
  await prefs.setString('last_opened_file', '/path/to/file.dart');
  await prefs.setInt('files_opened_count', 15);
}

// ok: insecure-shared-preferences-usage
class PreferencesService {
  static const _prefs = SharedPreferences.getInstance();
  
  // Все методы работают только с безопасными настройками
  Future<String> getTheme() async {
    final prefs = await _prefs;
    return prefs.getString('theme') ?? 'light';
  }
  
  Future<void> setTheme(String theme) async {
    final prefs = await _prefs;
    await prefs.setString('theme', theme);
  }
}

// =============================================================================
// ТЕСТЫ ДЛЯ ПРОВЕРКИ РЕГУЛЯРНЫХ ВЫРАЖЕНИЙ ПРАВИЛА
// =============================================================================

// Эти тесты проверяют, что правило корректно обрабатывает 
// различные вариации написания чувствительных ключей

// ruleid: insecure-shared-preferences-usage
Future<void> testRegexPatterns() async {
  final prefs = await SharedPreferences.getInstance();
  
  // camelCase
  await prefs.setString('apiKey', 'value');
  await prefs.setString('authToken', 'value');
  await prefs.setString('secretKey', 'value');
  
  // snake_case
  await prefs.setString('api_key', 'value');
  await prefs.setString('auth_token', 'value');
  await prefs.setString('secret_key', 'value');
  
  // kebab-case
  await prefs.setString('api-key', 'value');
  await prefs.setString('auth-token', 'value');
  await prefs.setString('secret-key', 'value');
  
  // UPPER_CASE
  await prefs.setString('API_KEY', 'value');
  await prefs.setString('AUTH_TOKEN', 'value');
  await prefs.setString('SECRET_KEY', 'value');
  
  // С префиксами/суффиксами
  await prefs.setString('prod_api_key', 'value');
  await prefs.setString('api_key_backup', 'value');
  await prefs.setString('user_auth_token', 'value');
  await prefs.setString('token_refresh', 'value');
}

// ok: insecure-shared-preferences-usage
Future<void> testFalsePositiveAvoidance() async {
  final prefs = await SharedPreferences.getInstance();
  
  // Слова, содержащие подстроки, но не являющиеся секретами
  await prefs.setString('keyboard_layout', 'qwerty');      // содержит "key"
  await prefs.setString('token_display', 'Gold');           // содержит "token"
  await prefs.setString('secret_menu_item', 'burger');      // содержит "secret"
  await prefs.setString('password_strength', 'strong');     // содержит "password"
  await prefs.setString('auth_flow_step', '2');             // содержит "auth"
  
  // Общие настройки
  await prefs.setString('app_name', 'MyApp');
  await prefs.setString('company_name', 'Example Inc');
  await prefs.setString('support_email', 'support@example.com');
}

// =============================================================================
// ТЕСТЫ ДЛЯ АСИНХРОННЫХ ПАТТЕРНОВ
// =============================================================================

// ruleid: insecure-shared-preferences-usage
Stream<String> authStream() async* {
  final prefs = await SharedPreferences.getInstance();
  // Сохранение в стриме
  yield await prefs.setString('stream_auth_token', 'token_from_stream');
}

// ruleid: insecure-shared-preferences-usage
Future<void> saveInIsolate() async {
  // Сохранение в контексте изолята
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('isolate_secret', 'secret_for_isolate');
}

// ok: insecure-shared-preferences-usage
Future<void> properAsyncPattern() async {
  const secureStorage = FlutterSecureStorage();
  // Правильный асинхронный паттерн с безопасным хранилищем
  await secureStorage.write(key: 'async_token', value: 'secure_value');
}

// =============================================================================
// ТЕСТЫ ДЛЯ EXTENSIONS И HELPER-МЕТОДОВ
// =============================================================================

// ruleid: insecure-shared-preferences-usage
extension AuthPrefs on SharedPreferences {
  Future<bool> saveCredentials(String token, String secret) {
    // Extension добавляет небезопасные методы
    return setString('auth_token', token) && 
           setString('auth_secret', secret);
  }
}

// ok: insecure-shared-preferences-usage
extension ThemePrefs on SharedPreferences {
  Future<bool> saveThemeSettings(String theme, String accent) {
    // Extension для безопасных настроек
    return setString('theme', theme) && 
           setString('accent_color', accent);
  }
}

// =============================================================================
// КОММЕНТАРИИ И ДОКУМЕНТАЦИЯ (не должны влиять на анализ)
// =============================================================================

/// Этот метод сохраняет токен аутентификации
/// 
/// Пример использования:
/// ```dart
/// await saveUserToken('eyJhbGci...');
/// ```
/// 
/// ⚠️ Внимание: этот метод использует SharedPreferences,
/// что не рекомендуется для чувствительных данных!
// ruleid: insecure-shared-preferences-usage
Future<void> saveUserToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('user_auth_token', token);
}

/**
 * Сохранение конфигурации API
 * 
 * @param config - объект конфигурации
 * @deprecated Используйте SecureConfigService вместо этого метода
 */
// ruleid: insecure-shared-preferences-usage
@deprecated
Future<void> saveApiConfig(Map<String, String> config) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('api_config', jsonEncode(config));
}