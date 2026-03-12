// test_clipboard_leakage.dart
// Тест для правила: clipboard-leakage
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/services.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: clipboard-leakage
const String PUBLIC_TEXT = 'Hello, world!';

// ok: clipboard-leakage
const String USER_NAME = 'John Doe';

// ok: clipboard-leakage
const String APP_VERSION = '1.0.0';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямое копирование чувствительных данных
// =============================================================================

void testDirectCopy1() {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: 'Password: 123456'));
}

void testDirectCopy2() {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: 'Secret token: abcdef'));
}

Future<void> testDirectCopy3() async {
  // ruleid: clipboard-leakage
  await Clipboard.setData(ClipboardData(text: 'My password is qwerty'));
}

Future<void> testDirectCopy4() async {
  // ruleid: clipboard-leakage
  await Clipboard.setData(ClipboardData(text: 'PIN: 1234'));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование переменных с чувствительными данными
// =============================================================================

void testVariableCopy1() {
  final String password = 'userPassword123';
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: password));
}

void testVariableCopy2() {
  final String token = 'authToken';
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: token));
}

void testVariableCopy3(String userPassword) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: userPassword));
}

Future<void> testVariableCopy4(String accessToken) async {
  // ruleid: clipboard-leakage
  await Clipboard.setData(ClipboardData(text: accessToken));
}

void testVariableCopy5() {
  final String apiKey = 'live_sk_123456';
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: apiKey));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование в обработчиках событий
// =============================================================================

class TestClass {
  String _userPassword = 'userpass';
  String authToken = 'token123';
  String secret = 'mySecret';

  void onCopyButtonPressed() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: _userPassword));
  }

  void onCopyToken() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: authToken));
  }

  void handleCopy() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: secret));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование в StatefulWidget
// =============================================================================

class MyWidget extends StatefulWidget {
  @override
  _MyWidgetState createState() => _MyWidgetState();
}

class _MyWidgetState extends State<MyWidget> {
  String _password = 'userpass';
  String _token = 'jwt.token.here';

  @override
  void initState() {
    super.initState();
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: _password));
  }

  void _copyToken() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: _token));
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        // ruleid: clipboard-leakage
        Clipboard.setData(ClipboardData(text: _password));
      },
      child: Container(),
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Условное копирование
// =============================================================================

void testConditionalCopy1(bool isAuthenticated, String userSecret) {
  if (isAuthenticated) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: userSecret));
  }
}

Future<void> testConditionalCopy2(String userSecret) async {
  if (userSecret.isNotEmpty) {
    // ruleid: clipboard-leakage
    await Clipboard.setData(ClipboardData(text: userSecret));
  }
}

void copyIfNeeded(String token) {
  if (token != null) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: token));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование с динамическим формированием строки
// =============================================================================

void testDynamicCopy1(String authToken) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: 'Bearer $authToken'));
}

Future<void> testDynamicCopy2(String token) async {
  // ruleid: clipboard-leakage
  await Clipboard.setData(ClipboardData(text: 'Token: $token'));
}

void testDynamicCopy3(String password) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: 'Secret: $password'));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование в асинхронных контекстах
// =============================================================================

Future<void> testAsyncCopy1() async {
  final String secret = await _fetchSecret();
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: secret));
}

void testAsyncCopy2() {
  Future.delayed(Duration(seconds: 1), () {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: 'Delayed secret'));
  });
}

Future<void> copyAfterFuture() async {
  final String data = await getToken();
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: data));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование через обёртки и хелперы
// =============================================================================

class ClipboardHelper {
  static void copySecret(String secret) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: secret));
  }

  static Future<void> copyToken(String token) async {
    // ruleid: clipboard-leakage
    await Clipboard.setData(ClipboardData(text: token));
  }
}

void copyUsingHelper(String password) {
  // ruleid: clipboard-leakage
  ClipboardHelper.copySecret(password);
}

class SecretManager {
  final String _secret;

  SecretManager(this._secret);

  void copyToClipboard() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: _secret));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Extension методы
// =============================================================================

extension UnsafeClipboard on String {
  void copyToClipboard() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: this));
  }
}

void testExtension(String password) {
  // ruleid: clipboard-leakage
  password.copyToClipboard();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование в фоновых задачах
// =============================================================================

void backgroundTask() {
  Timer(Duration(seconds: 5), () {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: 'Background secret'));
  });
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Копирование в try-catch
// =============================================================================

void testTryCatchCopy(String password) {
  try {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: password));
  } catch (e) {
    print(e);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Чтение из буфера обмена (не запись)
// =============================================================================

// ok: clipboard-leakage
Future<void> testGetData() async {
  final ClipboardData? data = await Clipboard.getData('text/plain');
  print(data?.text);
}

// ok: clipboard-leakage
Future<String?> readClipboard() async {
  final ClipboardData? data = await Clipboard.getData('text/plain');
  return data?.text;
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Копирование явно публичных/нечувствительных данных
// =============================================================================

// ok: clipboard-leakage
void testPublicCopy1() {
  Clipboard.setData(ClipboardData(text: PUBLIC_TEXT));
}

// ok: clipboard-leakage
void testPublicCopy2() {
  Clipboard.setData(ClipboardData(text: USER_NAME));
}

// ok: clipboard-leakage
void testPublicCopy3() {
  Clipboard.setData(ClipboardData(text: APP_VERSION));
}

// ok: clipboard-leakage
void testPublicCopy4() {
  Clipboard.setData(ClipboardData(text: 'Welcome to our app!'));
}

// ok: clipboard-leakage
Future<void> testPublicCopy5() async {
  await Clipboard.setData(ClipboardData(text: 'Hello, world!'));
}

// ok: clipboard-leakage
void testPublicCopy6() {
  Clipboard.setData(ClipboardData(text: 'Current time: ${DateTime.now()}'));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Копирование после подтверждения пользователя
// =============================================================================

// ok: clipboard-leakage
void copyAfterUserConsent(String data, bool userConsented) {
  if (userConsented) {
    Clipboard.setData(ClipboardData(text: data));
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Копирование в тестовом режиме
// =============================================================================

const bool kReleaseMode = false;

// ok: clipboard-leakage
void testDebugCopy() {
  if (!kReleaseMode) {
    Clipboard.setData(ClipboardData(text: 'Debug data'));
  }
}

// ok: clipboard-leakage
void testAssertCopy() {
  assert(() {
    Clipboard.setData(ClipboardData(text: 'Assert message'));
    return true;
  }());
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Строки и комментарии, не являющиеся кодом
// =============================================================================

// ok: clipboard-leakage
void testNonCode() {
  // Это просто строка, не выполняющийся код
  String comment = 'Clipboard.setData(ClipboardData(text: "password"))';
  
  // Это документация
  String doc = '''
    This is documentation:
    Clipboard.setData(ClipboardData(text: secret)) should not be used.
  ''';
  
  // Это конфигурация
  Map<String, String> config = {
    'copy_command': 'Clipboard.setData'
  };
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование других API (не Clipboard)
// =============================================================================

// ok: clipboard-leakage
void testOtherApis() {
  print('This is not a clipboard copy');
  StringBuffer buffer = StringBuffer();
  buffer.write('some text');
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Динамическое определение данных для копирования
// =============================================================================

void copyDynamic(String userInput) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: userInput));
}

// ok: clipboard-leakage
void copyPublicInput(String userInput) {
  // предполагаем, что входные данные публичны
  Clipboard.setData(ClipboardData(text: userInput));
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Копирование внутри виджета с наследованием
// =============================================================================

class InheritedClipboard extends InheritedWidget {
  final String secret;

  InheritedClipboard({required this.secret, required Widget child}) : super(child: child);

  @override
  bool updateShouldNotify(covariant InheritedWidget oldWidget) => false;
}

class ChildWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final InheritedClipboard? inherited = context.dependOnInheritedWidgetOfExactType<InheritedClipboard>();
    if (inherited != null) {
      // ruleid: clipboard-leakage
      Clipboard.setData(ClipboardData(text: inherited.secret));
    }
    return Container();
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Копирование в миксинах
// =============================================================================

mixin ClipboardMixin {
  String get secret;

  void copySecret() {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: secret));
  }
}

class MyClass with ClipboardMixin {
  @override
  String get secret => 'mixinSecret';
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Копирование в фабричных конструкторах
// =============================================================================

class SecretHolder {
  final String secret;

  SecretHolder._(this.secret);

  factory SecretHolder.fromString(String s) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: s));
    return SecretHolder._(s);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Копирование с использованием Stream
// =============================================================================

void subscribeToSecretStream(Stream<String> secrets) {
  secrets.listen((String secret) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: secret));
  });
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Копирование внутри операторов
// =============================================================================

void testOperators1(String password) {
  if (password.isNotEmpty) {
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: password));
  }
}

void testOperators2(String password) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: password ?? 'default'));
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полный жизненный цикл
// =============================================================================

class UserSession {
  String? _authToken;

  void login(String token) {
    _authToken = token;
    // ruleid: clipboard-leakage
    Clipboard.setData(ClipboardData(text: 'Login success, token: $_authToken'));
  }

  void copyToken() {
    if (_authToken != null) {
      // ruleid: clipboard-leakage
      Clipboard.setData(ClipboardData(text: _authToken!));
    }
  }

  void logout() {
    _authToken = null;
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации синтаксиса
// =============================================================================

void testSyntaxVariations1(String secret) {
  // ruleid: clipboard-leakage
  Clipboard.setData(ClipboardData(text: secret));
}

Future<void> testSyntaxVariations2(String secret) async {
  // ruleid: clipboard-leakage
  await Clipboard.setData(ClipboardData(text: secret));
}

// ok: clipboard-leakage
Future<void> testSyntaxVariations3() async {
  final ClipboardData? data = await Clipboard.getData('text/plain');
}

// ok: clipboard-leakage
void testSyntaxVariations4() {
  Clipboard.setData(ClipboardData(text: 'public info'));
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

// Вспомогательные функции для тестов
Future<String> _fetchSecret() async => 'asyncSecret';
Future<String> getToken() async => 'futureToken';