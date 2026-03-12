// test_insecure_deserialization.dart
// Тест для правила: insecure-deserialization-json
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:convert';
import 'dart:io';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: insecure-deserialization-json
const String SAFE_JSON = '{"name": "test", "id": 1}';

// ok: insecure-deserialization-json
const String TRUSTED_ENDPOINT = 'https://api.example.com';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode с пользовательским вводом
// =============================================================================

// ruleid: insecure-deserialization-json
final decoded1 = jsonDecode(userInput);

// ruleid: insecure-deserialization-json
final decoded2 = jsonDecode(requestBody);

// ruleid: insecure-deserialization-json
final decoded3 = jsonDecode(fileContent);

Future<void> testUserInputDeserialization(String userInput) async {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(userInput);

  // ruleid: insecure-deserialization-json
  final parsed = jsonDecode(userInput) as Map;

  // ruleid: insecure-deserialization-json
  final result = jsonDecode(userInput)['key'];
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode с данными из сети
// =============================================================================

// ruleid: insecure-deserialization-json
final networkData1 = jsonDecode(responseBody);

// ruleid: insecure-deserialization-json
final networkData2 = jsonDecode(httpResponse);

Future<void> testNetworkDeserialization(String responseBody) async {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(responseBody);

  // ruleid: insecure-deserialization-json
  final parsed = jsonDecode(await fetchFromApi());

  // ruleid: insecure-deserialization-json
  final result = jsonDecode(await response.body);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode с данными из файлов
// =============================================================================

// ruleid: insecure-deserialization-json
final fileData1 = jsonDecode(fileContent);

// ruleid: insecure-deserialization-json
final fileData2 = jsonDecode(await File(path).readAsString());

Future<void> testFileDeserialization(String fileContent, String path) async {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(fileContent);

  // ruleid: insecure-deserialization-json
  final parsed = jsonDecode(await File(path).readAsString());

  // ruleid: insecure-deserialization-json
  final result = jsonDecode(File(path).readAsStringSync());
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямая десериализация в конкретные типы
// =============================================================================

// ruleid: insecure-deserialization-json
final mapData = jsonDecode(untrustedJson) as Map<String, dynamic>;

// ruleid: insecure-deserialization-json
final listData = jsonDecode(untrustedJson) as List;

// ruleid: insecure-deserialization-json
final stringData = jsonDecode(untrustedJson) as String;

Future<void> testTypedDeserialization(String untrustedJson) async {
  // ruleid: insecure-deserialization-json
  final map = jsonDecode(untrustedJson) as Map<String, dynamic>;

  // ruleid: insecure-deserialization-json
  final list = jsonDecode(untrustedJson) as List<dynamic>;

  // ruleid: insecure-deserialization-json
  final nested = (jsonDecode(untrustedJson) as Map)['nested'] as Map;
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Цепочки вызовов с jsonDecode
// =============================================================================

// ruleid: insecure-deserialization-json
final value1 = jsonDecode(input)['user']['name'];

// ruleid: insecure-deserialization-json
final value2 = (jsonDecode(input) as Map).cast<String, dynamic>();

// ruleid: insecure-deserialization-json
final value3 = jsonDecode(input).toString();

Future<void> testChainedDeserialization(String input) async {
  // ruleid: insecure-deserialization-json
  final name = jsonDecode(input)['user']['name'];

  // ruleid: insecure-deserialization-json
  final data = (jsonDecode(input) as Map).cast<String, dynamic>();

  // ruleid: insecure-deserialization-json
  final count = (jsonDecode(input) as List).length;
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode в классах и сервисах
// =============================================================================

class InsecureParser {
  // ruleid: insecure-deserialization-json
  Map parse(String json) {
    return jsonDecode(json) as Map;
  }

  // ruleid: insecure-deserialization-json
  dynamic deserialize(String data) {
    return jsonDecode(data);
  }

  // ruleid: insecure-deserialization-json
  Future<Map> fetchAndParse() async {
    final response = await fetchFromApi();
    return jsonDecode(response) as Map;
  }
}

// ruleid: insecure-deserialization-json
class UnsafeDataService {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(externalData);

  // ruleid: insecure-deserialization-json
  void process(String input) {
    final parsed = jsonDecode(input);
    print(parsed);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode в callback-ах и обработчиках
// =============================================================================

// ruleid: insecure-deserialization-json
final parseCallback = (String json) => jsonDecode(json);

// ruleid: insecure-deserialization-json
void handleRequest(String body) {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(body);
  processData(data);
}

// ruleid: insecure-deserialization-json
final streamProcessor = StreamTransformer<String, dynamic>.fromHandlers(
  handleData: (data, sink) => sink.add(jsonDecode(data)),
);

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Условная десериализация
// =============================================================================

// ruleid: insecure-deserialization-json
final conditionalDecode = shouldParse ? jsonDecode(input) : defaultValue;

Future<void> testConditionalDeserialization(String input, bool shouldParse) async {
  // ruleid: insecure-deserialization-json
  if (isValid) {
    final data = jsonDecode(input);
  }

  // ruleid: insecure-deserialization-json
  final result = condition ? jsonDecode(input) : null;
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: jsonDecode с конкатенацией/интерполяцией
// =============================================================================

// ruleid: insecure-deserialization-json
final interpolatedDecode = jsonDecode('{"data": $userInput}');

// ruleid: insecure-deserialization-json
final concatDecode = jsonDecode(prefix + userInput + suffix);

Future<void> testDynamicJsonDeserialization(String userInput, String prefix, String suffix) async {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode('{"input": "$userInput"}');

  // ruleid: insecure-deserialization-json
  final parsed = jsonDecode(prefix + userInput);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Рекурсивная/вложенная десериализация
// =============================================================================

// ruleid: insecure-deserialization-json
final nestedDecode1 = jsonDecode(jsonDecode(outerJson));

// ruleid: insecure-deserialization-json
final nestedDecode2 = (jsonDecode(input) as Map)['nested'];

Future<void> testNestedDeserialization(String outerJson, String input) async {
  // ruleid: insecure-deserialization-json
  final outer = jsonDecode(outerJson);
  // ruleid: insecure-deserialization-json
  final inner = jsonDecode(outer['inner']);

  // ruleid: insecure-deserialization-json
  final deep = jsonDecode((jsonDecode(input) as Map)['nested']);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: jsonDecode с доверенными источниками
// =============================================================================

// ok: insecure-deserialization-json
final trusted1 = jsonDecode(SAFE_JSON);

// ok: insecure-deserialization-json
final trusted2 = jsonDecode(constJsonString);

Future<void> testTrustedDeserialization() async {
  // ok: insecure-deserialization-json
  final data = jsonDecode('{"name": "test", "id": 1}');

  // ok: insecure-deserialization-json
  final parsed = jsonDecode(CONFIG_JSON);

  // ok: insecure-deserialization-json
  final result = jsonDecode(localConstant);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Валидация перед десериализацией
// =============================================================================

// ok: insecure-deserialization-json
Future<void> testValidatedDeserialization(String input) async {
  // ok: insecure-deserialization-json
  if (!isValidJson(input)) return;
  // ok: insecure-deserialization-json
  final data = jsonDecode(input);
}

// ok: insecure-deserialization-json
Future<void> testSanitizedDeserialization(String input) async {
  // ok: insecure-deserialization-json
  final sanitized = sanitizeInput(input);
  // ok: insecure-deserialization-json
  final data = jsonDecode(sanitized);
}

// ok: insecure-deserialization-json
Future<void> testWhitelistDeserialization(String input) async {
  // ok: insecure-deserialization-json
  if (!allowedSources.contains(source)) return;
  // ok: insecure-deserialization-json
  final data = jsonDecode(input);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Try-catch с обработкой ошибок
// =============================================================================

// ok: insecure-deserialization-json
Future<void> testSafeTryCatch(String input) async {
  try {
    // ok: insecure-deserialization-json
    final data = jsonDecode(input);
    processData(data);
  } catch (e) {
    // ok: insecure-deserialization-json
    print('Invalid JSON: $e');
  }
}

// ok: insecure-deserialization-json
dynamic safeDecode(String input) {
  try {
    // ok: insecure-deserialization-json
    return jsonDecode(input);
  } catch (e) {
    return defaultValue;
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование jsonDecode для примитивов
// =============================================================================

// ok: insecure-deserialization-json
final primitive1 = jsonDecode('true') as bool;

// ok: insecure-deserialization-json
final primitive2 = jsonDecode('123') as int;

// ok: insecure-deserialization-json
final primitive3 = jsonDecode('"string"') as String;

Future<void> testPrimitiveDeserialization() async {
  // ok: insecure-deserialization-json
  final boolVal = jsonDecode('true') as bool;

  // ok: insecure-deserialization-json
  final intVal = jsonDecode('42') as int;

  // ok: insecure-deserialization-json
  final stringVal = jsonDecode('"hello"') as String;
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные классы и сервисы
// =============================================================================

class SafeParser {
  // ok: insecure-deserialization-json
  Map parse(String json) {
    // ok: insecure-deserialization-json
    if (!isValidJson(json)) throw FormatException('Invalid JSON');
    return jsonDecode(json) as Map;
  }

  // ok: insecure-deserialization-json
  dynamic deserialize(String data, {required bool trusted}) {
    // ok: insecure-deserialization-json
    if (!trusted) throw ArgumentError('Untrusted source');
    return jsonDecode(data);
  }
}

// ok: insecure-deserialization-json
class ValidatedDataService {
  // ok: insecure-deserialization-json
  final data = jsonDecode(trustedSource);

  // ok: insecure-deserialization-json
  void process(String input) {
    // ok: insecure-deserialization-json
    if (input.hashCode != expectedHash) return;
    final parsed = jsonDecode(input);
    print(parsed);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная валидация
// =============================================================================

// ruleid: insecure-deserialization-json
Future<void> testPartialValidation(String input) async {
  // ok: insecure-deserialization-json (эта проверка полезна)
  if (input.isEmpty) return;
  // ruleid: insecure-deserialization-json (но этого недостаточно)
  final data = jsonDecode(input);
}

// ruleid: insecure-deserialization-json
Future<void> testIncompleteSanitization(String input) async {
  // ruleid: insecure-deserialization-json (неполная санитизация)
  final sanitized = input.replaceAll('<', '');
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(sanitized);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

extension UnsafeJson on String {
  // ruleid: insecure-deserialization-json
  dynamic parseJson() => jsonDecode(this);

  // ruleid: insecure-deserialization-json
  Map toMap() => jsonDecode(this) as Map;
}

extension SafeJson on String {
  // ok: insecure-deserialization-json
  dynamic parseJsonSafe() {
    // ok: insecure-deserialization-json
    if (!isValidJson(this)) return null;
    return jsonDecode(this);
  }

  // ok: insecure-deserialization-json
  Map? toMapSafe() {
    try {
      // ok: insecure-deserialization-json
      return jsonDecode(this) as Map;
    } catch (e) {
      return null;
    }
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Фабрики и конструкторы
// =============================================================================

// ruleid: insecure-deserialization-json
class JsonFactory {
  // ruleid: insecure-deserialization-json
  static dynamic parse(String json) => jsonDecode(json);

  // ruleid: insecure-deserialization-json
  static Map parseMap(String json) => jsonDecode(json) as Map;
}

// ok: insecure-deserialization-json
class SafeJsonFactory {
  // ok: insecure-deserialization-json
  static dynamic parse(String json) {
    // ok: insecure-deserialization-json
    if (!isValidJson(json)) throw FormatException();
    return jsonDecode(json);
  }

  // ok: insecure-deserialization-json
  static Map? parseMapSafe(String json) {
    try {
      // ok: insecure-deserialization-json
      return jsonDecode(json) as Map;
    } catch (e) {
      return null;
    }
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Асинхронные паттерны
// =============================================================================

// ruleid: insecure-deserialization-json
Stream<dynamic> testStreamDeserialization(Stream<String> input) {
  return input.map((json) => jsonDecode(json));
}

// ruleid: insecure-deserialization-json
Future<dynamic> testFutureDeserialization(Future<String> input) async {
  return jsonDecode(await input);
}

// ok: insecure-deserialization-json
Stream<dynamic> testSafeStreamDeserialization(Stream<String> input) {
  return input
      .where((json) => isValidJson(json))
      .map((json) => jsonDecode(json));
}

// ok: insecure-deserialization-json
Future<dynamic?> testSafeFutureDeserialization(Future<String> input) async {
  try {
    final data = await input;
    // ok: insecure-deserialization-json
    if (!isValidJson(data)) return null;
    return jsonDecode(data);
  } catch (e) {
    return null;
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: jsonDecode в assert (безопасно)
// =============================================================================

// ok: insecure-deserialization-json
void testAssertDeserialization() {
  // ok: insecure-deserialization-json
  assert(() {
    final test = jsonDecode('{"test": true}');
    return test != null;
  }());
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Multiple jsonDecode calls
// =============================================================================

// ruleid: insecure-deserialization-json
Future<void> testMultipleDecodes(String input1, String input2) async {
  // ruleid: insecure-deserialization-json
  final data1 = jsonDecode(input1);
  // ruleid: insecure-deserialization-json
  final data2 = jsonDecode(input2);
  processData(data1, data2);
}

// ok: insecure-deserialization-json
Future<void> testSafeMultipleDecodes(String input1, String input2) async {
  // ok: insecure-deserialization-json
  if (!isValidJson(input1) || !isValidJson(input2)) return;
  // ok: insecure-deserialization-json
  final data1 = jsonDecode(input1);
  // ok: insecure-deserialization-json
  final data2 = jsonDecode(input2);
  processData(data1, data2);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Комментарии и строки (не код)
// =============================================================================

void testStringNotCode() {
  // ok: insecure-deserialization-json
  final comment = 'jsonDecode(input) is dangerous with untrusted input';

  // ok: insecure-deserialization-json
  final docString = 'Use jsonDecode only with validated JSON strings';

  // ok: insecure-deserialization-json
  final config = {'parser': 'jsonDecode', 'validate': 'true'};

  // ok: insecure-deserialization-json
  print('Warning: Validate JSON before calling jsonDecode');
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полные сценарии использования
// =============================================================================

// ruleid: insecure-deserialization-json
class InsecureApiHandler {
  // ruleid: insecure-deserialization-json
  Future<void> handleRequest(HttpRequest request) async {
    final body = await utf8.decoder.bind(request).join();
    // ruleid: insecure-deserialization-json
    final data = jsonDecode(body);
    // ruleid: insecure-deserialization-json
    processUserData(data);
  }

  // ruleid: insecure-deserialization-json
  dynamic parseResponse(String response) {
    return jsonDecode(response);
  }
}

// ok: insecure-deserialization-json
class SecureApiHandler {
  // ok: insecure-deserialization-json
  Future<void> handleRequest(HttpRequest request) async {
    final body = await utf8.decoder.bind(request).join();
    // ok: insecure-deserialization-json
    if (!isValidJson(body)) {
      request.response.statusCode = 400;
      return;
    }
    // ok: insecure-deserialization-json
    final data = jsonDecode(body);
    processUserData(data);
  }

  // ok: insecure-deserialization-json
  dynamic parseResponse(String response) {
    // ok: insecure-deserialization-json
    try {
      return jsonDecode(response);
    } catch (e) {
      throw FormatException('Invalid JSON response');
    }
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации написания
// =============================================================================

Future<void> testDetectionVariations(String input) async {
  // ruleid: insecure-deserialization-json
  final v1 = jsonDecode(input);

  // ruleid: insecure-deserialization-json
  final v2 = jsonDecode(input) as Map;

  // ruleid: insecure-deserialization-json
  final v3 = (jsonDecode(input) as Map)['key'];

  // ruleid: insecure-deserialization-json
  final v4 = jsonDecode(input)['nested']['value'];

  // ok: insecure-deserialization-json
  final safe1 = jsonDecode(SAFE_JSON);

  // ok: insecure-deserialization-json
  final safe2 = jsonDecode(constantJson);

  // ok: insecure-deserialization-json
  final safe3 = jsonDecode(input) as Map; // С валидацией выше
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testContextAnalysis() {
  // ok: insecure-deserialization-json
  final comment = 'jsonDecode(input) should be validated first';

  // ok: insecure-deserialization-json
  final docString = 'Never use jsonDecode on untrusted input';

  // ok: insecure-deserialization-json
  print('Warning: jsonDecode can throw on invalid JSON');
}

// ruleid: insecure-deserialization-json
Future<void> testActualVulnerableCode(String userInput) async {
  // ruleid: insecure-deserialization-json
  final data = jsonDecode(userInput);
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

bool isValidJson(String input) {
  try {
    jsonDecode(input);
    return true;
  } catch (e) {
    return false;
  }
}

String sanitizeInput(String input) => input.trim();
void processData(dynamic data1, [dynamic data2]) {}
void processUserData(dynamic data) {}
Future<String> fetchFromApi() async => '{}';
dynamic defaultValue = {};

// Глобальные переменные для тестов
String userInput = '{}';
String requestBody = '{}';
String fileContent = '{}';
String responseBody = '{}';
String httpResponse = '{}';
String untrustedJson = '{}';
String input = '{}';
String externalData = '{}';
String outerJson = '{}';
String path = '/tmp/file.json';
String source = 'unknown';
String prefix = '{"data":';
String suffix = '}';
String constJsonString = '{"constant": true}';
String CONFIG_JSON = '{"config": true}';
String localConstant = '{"local": true}';
String trustedSource = '{"trusted": true}';
String expectedHash = 'abc123';
List<String> allowedSources = ['trusted'];
bool shouldParse = true;
bool isValid = true;
bool condition = true;
dynamic defaultValue = {};
var config = const {'parser': 'jsonDecode'};