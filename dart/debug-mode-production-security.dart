// test_debug_mode_production.dart
// Тест для правила: debug-mode-production-security
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: debug-mode-production-security
const String APP_VERSION = '1.0.0';

// ok: debug-mode-production-security
const String PRODUCTION_API_URL = 'https://api.example.com';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в проверках аутентификации
// =============================================================================

Future<bool> testDebugAuthBypass() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode == true) return true;

  // ruleid: debug-mode-production-security
  return kDebugMode ? true : await validateAuth();
}

// Глобальная переменная для теста присваивания
// ruleid: debug-mode-production-security
final skipAuthGlobal = kDebugMode;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в проверках авторизации
// =============================================================================

Future<bool> testDebugAuthzBypass(String userId) async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode) return hasPermission(userId, 'admin');

  // ruleid: debug-mode-production-security
  return kDebugMode || userIsAdmin;
}

// ruleid: debug-mode-production-security
final isAdminGlobal = kDebugMode ? true : userRole == 'admin';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в валидации данных
// =============================================================================

Future<bool> testDebugValidationBypass(String input) async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode) return isValid(input);

  // ruleid: debug-mode-production-security
  return kDebugMode ? true : validateInput(input);
}

// ruleid: debug-mode-production-security
final skipValidationGlobal = kDebugMode;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в проверках лицензии
// =============================================================================

Future<bool> testDebugLicenseBypass() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode) return validateLicense();

  // ruleid: debug-mode-production-security
  return kDebugMode || await verifyLicense();
}

// ruleid: debug-mode-production-security
final isLicensedGlobal = kDebugMode ? true : false;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в проверках подписи
// =============================================================================

Future<bool> testDebugSignatureBypass() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode) return validateSignature();

  // ruleid: debug-mode-production-security
  return kDebugMode ? true : await verifySignature();
}

// ruleid: debug-mode-production-security
final isSignedGlobal = kDebugMode ? true : verifySignatureData(data);

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kReleaseMode инверсия (опасно)
// =============================================================================

Future<bool> testReleaseModeBypass() async {
  // ruleid: debug-mode-production-security
  if (!kReleaseMode) return true;

  // ruleid: debug-mode-production-security
  if (!kReleaseMode) return validateAuth();

  // ruleid: debug-mode-production-security
  return !kReleaseMode ? true : await checkSecurity();
}

// ruleid: debug-mode-production-security
final skipCheckGlobal = !kReleaseMode;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kProfileMode в безопасности
// =============================================================================

Future<bool> testProfileModeBypass() async {
  // ruleid: debug-mode-production-security
  if (kProfileMode) return true;

  // ruleid: debug-mode-production-security
  if (kProfileMode) return skipValidation();
}

// ruleid: debug-mode-production-security
final skipInProfileGlobal = kProfileMode;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Комбинированные проверки режимов
// =============================================================================

Future<bool> testCombinedModeBypass() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode || kProfileMode) return true;

  // ruleid: debug-mode-production-security
  if (!kReleaseMode) return bypassSecurity();

  // ruleid: debug-mode-production-security
  return (kDebugMode || kProfileMode) ? true : await validate();
}

// ruleid: debug-mode-production-security
final skipInDebugOrProfileGlobal = kDebugMode || kProfileMode;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Классы с уязвимостями
// =============================================================================

class DebugAuthService {

  Future<bool> authenticate(String token) async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return await validateToken(token);
  }


  bool isAdmin() {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return userRole == 'admin';
  }

  Future<bool> checkLicense() async {
    // ruleid: debug-mode-production-security
    return kDebugMode ? true : await verifyLicense();
  }
}

class InsecureValidator {
  bool validate(String input) {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return input.isNotEmpty;
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Тернарные операторы с kDebugMode
// =============================================================================

// ruleid: debug-mode-production-security
final authResultGlobal = kDebugMode ? true : false;

// ruleid: debug-mode-production-security
final permissionGlobal = kDebugMode ? true : userPermission;

// ruleid: debug-mode-production-security
final validationResultGlobal = kDebugMode ? true : validate();

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Логические операторы с kDebugMode
// =============================================================================

// ruleid: debug-mode-production-security
final canAccessGlobal = kDebugMode || userIsAdmin;

// ruleid: debug-mode-production-security
final skipValidationLogic = kDebugMode || configSkipValidation;

// ruleid: debug-mode-production-security
final bypassSecurityLogic = kDebugMode && configAllowBypass;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в конструкторах
// =============================================================================

class DebugConfig {
  // ruleid: debug-mode-production-security
  final skipAuth = kDebugMode;

  // ruleid: debug-mode-production-security
  DebugConfig() : skipValidation = kDebugMode;
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в инициализаторах
// =============================================================================

// ruleid: debug-mode-production-security
final configGlobal = AppConfig(skipAuth: kDebugMode);

// ruleid: debug-mode-production-security
final settingsGlobal = SecuritySettings(bypassValidation: kDebugMode);

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: kDebugMode в callback-ах
// =============================================================================

// ruleid: debug-mode-production-security
final authCallback = () => kDebugMode ? true : validateAuth();

VoidCallback debugCallback = () {
  // ruleid: debug-mode-production-security
  if (kDebugMode) navigateToAdmin();
};

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование kDebugMode (логирование)
// =============================================================================

Future<void> testSafeDebugLogging() async {
  // ok: debug-mode-production-security
  if (kDebugMode) print('Debug: User logged in');

  // ok: debug-mode-production-security
  if (kDebugMode) debugPrint('API Response: $response');

  // ok: debug-mode-production-security
  if (kDebugMode) logger.d('Debug log message');
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование kDebugMode (UI)
// =============================================================================

Widget buildDebugBanner() => kDebugMode ? const DebugBanner() : const Container();

Future<Widget> testSafeDebugUI() async {
  // ok: debug-mode-production-security
  return kDebugMode ? const DebugWidget() : const NormalWidget();

  // ok: debug-mode-production-security
  if (kDebugMode) return const DebugScreen();

  // ok: debug-mode-production-security
  return kDebugMode ? buildDebugUI() : buildProductionUI();
}

void showDebugOverlayIfDebug() {
  // ok: debug-mode-production-security
  if (kDebugMode) showDebugOverlay();
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование kDebugMode (отладка)
// =============================================================================

Future<void> testSafeDebugFeatures() async {
  // ok: debug-mode-production-security
  if (kDebugMode) await debugDelay(1000);

  // ok: debug-mode-production-security
  if (kDebugMode) enableDebugFeatures();

  // ok: debug-mode-production-security
  if (kDebugMode) await Future.delayed(const Duration(seconds: 1));

  // ok: debug-mode-production-security
  if (kDebugMode) showDebugMenu();

  // ok: debug-mode-production-security
  if (kDebugMode) enableProfiler();
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: kReleaseMode для оптимизаций (безопасно)
// =============================================================================

Future<void> testSafeReleaseMode() async {
  // ok: debug-mode-production-security
  if (kReleaseMode) enableOptimizations();

  // ok: debug-mode-production-security
  if (kReleaseMode) disableDebugFeatures();
}

// ok: debug-mode-production-security
final useCacheGlobal = kReleaseMode;

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные классы
// =============================================================================

class SafeDebugService {
  // ok: debug-mode-production-security
  void logDebug(String message) {
    // ok: debug-mode-production-security
    if (kDebugMode) print(message);
  }

  // ok: debug-mode-production-security
  Widget buildUI() {
    // ok: debug-mode-production-security
    return kDebugMode ? const DebugWidget() : const ProductionWidget();
  }

  // ok: debug-mode-production-security
  Future<void> init() async {
    // ok: debug-mode-production-security
    if (kDebugMode) await debugInit();
    await productionInit();
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: kDebugMode вне контекста безопасности
// =============================================================================

// ok: debug-mode-production-security
final debugLabelGlobal = kDebugMode ? '[DEBUG]' : '';

void showDevToolsIfDebug() {
  // ok: debug-mode-production-security
  if (kDebugMode) showDevTools();
}

// ok: debug-mode-production-security
final verboseLoggingGlobal = kDebugMode;

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: kDebugMode с дополнительными проверками
// =============================================================================

Future<bool> testConditionalBypass() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode && configAllowDebugBypass) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode || testMode) return skipAuth();
}

// ruleid: debug-mode-production-security
final bypassConditional = kDebugMode && isAdminUser;

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: kDebugMode в assert (безопасно)
// =============================================================================

void testAsserts() {
  // ok: debug-mode-production-security
  assert(kDebugMode, 'This should only run in debug mode');

  // ok: debug-mode-production-security
  assert(() {
    // ok: debug-mode-production-security
    if (kDebugMode) print('Debug assertion');
    return true;
  }());
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: kDebugMode в тестах
// =============================================================================

// ok: debug-mode-production-security
@visibleForTesting
Future<void> setupTest() async {
  // ok: debug-mode-production-security
  if (kDebugMode) await setupDebugTest();
}

class TestHelper {
  // ok: debug-mode-production-security
  @visibleForTesting
  void enableTestMode() {
    // ok: debug-mode-production-security
    if (kDebugMode) testModeEnabled = true;
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Environment variables с kDebugMode
// =============================================================================

// ruleid: debug-mode-production-security
final skipAuthEnv = kDebugMode || (Platform.environment['SKIP_AUTH'] == 'true');

Future<bool> testEnvWithDebug() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode || (Platform.environment['DEBUG'] == 'true')) return true;

  // ruleid: debug-mode-production-security
  return (kDebugMode || testMode) ? true : await validate();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Наследование и переопределение
// =============================================================================

class DebugAuthServiceSub extends AuthService {
  @override
  Future<bool> authenticate(String token) async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return super.authenticate(token);
  }
}

class SafeDebugServiceSub extends AuthService {
  @override
  // ok: debug-mode-production-security
  Future<bool> authenticate(String token) async {
    // ok: debug-mode-production-security
    if (kDebugMode) print('Auth attempt: $token');
    return super.authenticate(token);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

extension DebugAuth on User {
  Future<bool> canAccess() async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return await validateAccess();
  }
}

extension DebugLog on User {
  // ok: debug-mode-production-security
  void logAction(String action) {
    // ok: debug-mode-production-security
    if (kDebugMode) print('User $id performed $action');
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Асинхронные паттерны
// =============================================================================

Stream<bool> testDebugStream() async* {
  // ruleid: debug-mode-production-security
  if (kDebugMode) yield true;
  yield await validate();
}

Future<bool> testDebugFuture() async {
  // ruleid: debug-mode-production-security
  return kDebugMode ? true : await checkSecurity();
}

Stream<void> testSafeStream() async* {
  // ok: debug-mode-production-security
  if (kDebugMode) yield* debugStream();
  yield* productionStream();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Константы и конфигурация
// =============================================================================

// ruleid: debug-mode-production-security
const bool SKIP_AUTH_IN_DEBUG = kDebugMode;

// ruleid: debug-mode-production-security
final configConst = SecurityConfig(bypassAuth: kDebugMode);

// ok: debug-mode-production-security
const bool ENABLE_DEBUG_LOGGING = kDebugMode;

// ok: debug-mode-production-security
final configDebug = DebugConfig(verboseLogging: kDebugMode);

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Multiple conditions
// =============================================================================

Future<bool> testMultipleConditions() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode || kProfileMode || testMode) return true;

  // ruleid: debug-mode-production-security
  if (!kReleaseMode && !configForceSecurity) return true;
}

// ruleid: debug-mode-production-security
final bypassMulti = kDebugMode || kProfileMode || configTestMode;

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полные сценарии использования
// =============================================================================

class InsecureProductionApp {
  // ruleid: debug-mode-production-security
  Future<bool> login(String username, String password) async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return await authProvider.login(username, password);
  }

  Future<bool> isAdmin() async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return true;
    return userRole == 'admin';
  }

  Future<void> processPayment(double amount) async {
    // ruleid: debug-mode-production-security
    if (kDebugMode) return;
    await paymentGateway.charge(amount);
  }
}

class SecureProductionApp {
  // ok: debug-mode-production-security
  Future<bool> login(String username, String password) async {
    // ok: debug-mode-production-security
    if (kDebugMode) print('Login attempt: $username');
    return await authProvider.login(username, password);
  }

  // ok: debug-mode-production-security
  Future<bool> isAdmin() async {
    // ok: debug-mode-production-security
    if (kDebugMode) print('Checking admin status for: $userId');
    return userRole == 'admin';
  }

  // ok: debug-mode-production-security
  Future<void> processPayment(double amount) async {
    // ok: debug-mode-production-security
    if (kDebugMode) print('Processing payment: \$$amount');
    await paymentGateway.charge(amount);
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации написания
// =============================================================================

Future<void> testDetectionVariations() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return true;

  // ruleid: debug-mode-production-security
  if (kDebugMode == true) return true;

  // ruleid: debug-mode-production-security
  if (true == kDebugMode) return true;

  // ruleid: debug-mode-production-security
  final bypassVar = kDebugMode;

  // ruleid: debug-mode-production-security
  return kDebugMode ? true : await validate();

  // ok: debug-mode-production-security
  if (kDebugMode) print('debug');

  // ok: debug-mode-production-security
  final debugVar = kDebugMode;

  // ok: debug-mode-production-security
  return kDebugMode ? const DebugWidget() : const ProductionWidget();
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testContextAnalysis() {
  // ok: debug-mode-production-security
  final comment = 'if (kDebugMode) return true; // This is dangerous!';

  // ok: debug-mode-production-security
  final docString = 'Do not use kDebugMode for security checks';

  // ok: debug-mode-production-security
  print('Warning: kDebugMode should not bypass security');
}

Future<void> testActualVulnerableCode() async {
  // ruleid: debug-mode-production-security
  if (kDebugMode) return bypassSecurity();
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

Future<bool> validateAuth() async => true;
Future<bool> validateToken(String token) async => true;
Future<bool> verifyLicense() async => true;
Future<bool> verifySignature() async => true;
bool verifySignatureData(dynamic d) => true;
Future<bool> validate() async => true;
Future<bool> checkSecurity() async => true;
Future<bool> skipAuth() async => true;
Future<bool> bypassSecurity() async => true;
bool isValid(String input) => true;
bool validateInput(String input) => true;
bool hasPermission(String userId, String permission) => true;
bool validateSignature() => true;
Future<bool> checkLicense() async => true;
Future<void> setupDebugTest() async {}
Future<void> debugInit() async {}
Future<void> productionInit() async {}
Future<bool> validateAccess() async => true;
Stream<void> debugStream() async* {}
Stream<void> productionStream() async* {}
void showDebugOverlay() {}
Widget buildDebugUI() => const SizedBox();
Widget buildProductionUI() => const SizedBox();
void enableDebugFeatures() {}
void showDebugMenu() {}
void enableProfiler() {}
void enableOptimizations() {}
void disableDebugFeatures() {}
void showDevTools() {}
void navigateToAdmin() {}
void debugDelay(int ms) {}

// Глобальные переменные для тестов
bool testMode = false;
String userRole = 'user';
bool userIsAdmin = false;
String userPermission = 'read';
bool isAdminUser = false;
bool configSkipValidation = false;
bool configAllowBypass = false;
bool configAllowDebugBypass = false;
bool configTestMode = false;
bool configForceSecurity = false;
bool testModeEnabled = false;
String data = 'test';
String response = 'test';
String userId = '1';
String id = '1';
var logger = Logger();
class Logger {
  void d(String msg) {}
}
var authProvider = AuthProvider();
class AuthProvider {
  Future<bool> login(String u, String p) async => true;
}
var paymentGateway = PaymentGateway();
class PaymentGateway {
  Future<void> charge(double amount) async {}
}
class DebugBanner extends StatelessWidget {
  const DebugBanner({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}
class DebugWidget extends StatelessWidget {
  const DebugWidget({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}
class NormalWidget extends StatelessWidget {
  const NormalWidget({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}
class DebugScreen extends StatelessWidget {
  const DebugScreen({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}
class ProductionWidget extends StatelessWidget {
  const ProductionWidget({super.key});
  @override
  Widget build(BuildContext context) => const SizedBox();
}
class User {}
class AuthService {
  Future<bool> authenticate(String token) async => true;
}
class SecurityConfig {
  const SecurityConfig({this.bypassAuth = false});
  final bool bypassAuth;
}
class DebugConfig {
  const DebugConfig({this.verboseLogging = false});
  final bool verboseLogging;
  const DebugConfig() : skipValidation = false;
  final bool skipValidation;
}
class AppConfig {
  const AppConfig({this.skipAuth = false});
  final bool skipAuth;
}
class SecuritySettings {
  const SecuritySettings({this.bypassValidation = false});
  final bool bypassValidation;
}