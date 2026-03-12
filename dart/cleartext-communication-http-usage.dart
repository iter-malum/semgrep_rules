// test_cleartext_communication.dart
// Тест для правила: cleartext-communication-http-usage
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:io';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:dio/dio.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:flutter/material.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: cleartext-communication-http-usage
const String API_BASE_URL = 'https://api.example.com/v1';

// ok: cleartext-communication-http-usage
const String DOCS_URL = 'https://docs.example.com';

// ok: cleartext-communication-http-usage
const String FTP_URL = 'ftp://files.example.com/data';

// ok: cleartext-communication-http-usage
const String WEBSOCKET_SECURE = 'wss://ws.example.com/stream';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямое использование http://
// =============================================================================

Future<void> testBasicHttpMethods() async {
  // ruleid: cleartext-communication-http-usage
  final response1 = await http.get(Uri.parse('http://api.example.com/users'));

  // ruleid: cleartext-communication-http-usage
  final response2 = await http.post(Uri.parse('http://auth.example.com/login'));

  // ruleid: cleartext-communication-http-usage
  final response3 = await http.put(Uri.parse('http://api.example.com/users/123'));

  // ruleid: cleartext-communication-http-usage
  final response4 = await http.delete(Uri.parse('http://api.example.com/items/456'));

  // ruleid: cleartext-communication-http-usage
  final response5 = await http.patch(Uri.parse('http://api.example.com/settings'));

  // ruleid: cleartext-communication-http-usage
  final response6 = await http.head(Uri.parse('http://cdn.example.com/file.zip'));

  // ruleid: cleartext-communication-http-usage
  final response7 = await http.options(Uri.parse('http://api.example.com/cors'));
}

// =============================================================================
// Uri.* конструкторы с http://
// =============================================================================

Future<void> testUriConstructors() async {
  // ruleid: cleartext-communication-http-usage
  final uri1 = Uri.http('api.example.com', '/users/123');

  // ruleid: cleartext-communication-http-usage
  final uri2 = Uri(scheme: 'http', host: 'api.example.com', path: '/data');

  // ruleid: cleartext-communication-http-usage
  final insecure = Uri.parse('http://api.example.com/insecure');
}

// =============================================================================
// HttpClient (dart:io)
// =============================================================================

Future<void> testHttpClient() async {
  // ruleid: cleartext-communication-http-usage
  final request1 = await HttpClient().getUrl(Uri.parse('http://api.example.com/data'));

  // ruleid: cleartext-communication-http-usage
  final request2 = await HttpClient().postUrl(Uri.parse('http://api.example.com/submit'));

  // ruleid: cleartext-communication-http-usage
  final client1 = IOClient(HttpClient());
  final response8 = await client1.get(Uri.parse('http://legacy.example.com/api'));
}

// =============================================================================
// Dio клиент
// =============================================================================

Future<void> testDioClient() async {
  final dio1 = Dio();
  
  // ruleid: cleartext-communication-http-usage
  final response9 = await dio1.get('http://api.example.com/users');

  // ruleid: cleartext-communication-http-usage
  await dio1.post('http://auth.example.com/login', data: {'user': 'admin'});

  // ruleid: cleartext-communication-http-usage
  final dio2 = Dio(BaseOptions(baseUrl: 'http://api.example.com'));
}

// =============================================================================
// Динамическое построение URL
// =============================================================================

Future<void> testDynamicUrls(String endpoint, String userId, String resource, String id, String query) async {
  // ruleid: cleartext-communication-http-usage
  final url1 = 'http://api.example.com/$endpoint';

  // ruleid: cleartext-communication-http-usage
  final url2 = 'http://api.example.com/users/' + userId;

  // ruleid: cleartext-communication-http-usage
  final url3 = 'http://api.example.com/$resource/$id';

  // ruleid: cleartext-communication-http-usage
  final url4 = 'http://search.example.com?q=$query';
}

class ConfigTest {
  // ruleid: cleartext-communication-http-usage
  static const baseUrl = 'http://api.example.com';

  // ruleid: cleartext-communication-http-usage
  String getEnvUrl() => String.fromEnvironment('API_URL', defaultValue: 'http://default.com');
}

// =============================================================================
// WebSocket и другие протоколы
// =============================================================================

Future<void> testWebSocket() async {
  // ruleid: cleartext-communication-http-usage
  final ws1 = WebSocketChannel.connect(Uri.parse('ws://ws.example.com/stream'));

  // ruleid: cleartext-communication-http-usage
  final customUri = Uri.parse('custom+http://api.example.com/data');
}

// =============================================================================
// Условное использование HTTP
// =============================================================================

Future<void> testConditionalUrls(bool useHttp, bool isDebug, String env) async {
  // ruleid: cleartext-communication-http-usage
  final conditionalUrl = useHttp ? 'http://api.example.com/data' : 'https://api.example.com/data';

  // ruleid: cleartext-communication-http-usage
  final scheme = isDebug ? 'http' : 'https';

  // ruleid: cleartext-communication-http-usage
  final envScheme = env == 'production' ? 'https' : 'http';
}

// =============================================================================
// Ретраи и цепочки запросов
// =============================================================================

Future<void> testRetryPattern() async {
  // ruleid: cleartext-communication-http-usage
  final retryUrl = Uri.parse('http://api.example.com/data');

  // ruleid: cleartext-communication-http-usage
  final firstReq = await http.get(Uri.parse('http://api.example.com/token'));
}

// =============================================================================
// Стриминг и файлы
// =============================================================================

Future<void> testFileOperations() async {
  // ruleid: cleartext-communication-http-usage
  final downloadReq = http.Request('GET', Uri.parse('http://cdn.example.com/file.zip'));

  // ruleid: cleartext-communication-http-usage
  final uploadUri = Uri.parse('http://upload.example.com/files');

  // ruleid: cleartext-communication-http-usage
  final streamReq = http.Request('POST', Uri.parse('http://stream.example.com/upload'));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование
// =============================================================================

Future<void> testSecureHttps() async {
  // ok: cleartext-communication-http-usage
  final secure1 = await http.get(Uri.parse('https://api.example.com/users'));

  // ok: cleartext-communication-http-usage
  final secure2 = await http.post(Uri.parse('https://auth.example.com/login'));

  // ok: cleartext-communication-http-usage
  final secure3 = Uri.https('api.example.com', '/users/123');

  // ok: cleartext-communication-http-usage
  final secure4 = Uri(scheme: 'https', host: 'api.example.com', path: '/data');

  // ok: cleartext-communication-http-usage
  final wss1 = WebSocketChannel.connect(Uri.parse('wss://ws.example.com/stream'));
}

Future<void> testLocalhostExceptions() async {
  // ok: cleartext-communication-http-usage
  final local1 = await http.get(Uri.parse('http://localhost:8080/api'));

  // ok: cleartext-communication-http-usage
  final local2 = await http.get(Uri.parse('http://127.0.0.1:3000/data'));

  // ok: cleartext-communication-http-usage
  final local3 = Uri.http('localhost:8080', '/api/users');

  // ok: cleartext-communication-http-usage
  final privateNet1 = await http.get(Uri.parse('http://192.168.1.100:8080/api'));

  // ok: cleartext-communication-http-usage
  final privateNet2 = await http.get(Uri.parse('http://10.0.0.50:3000/data'));
}

Future<void> testNonHttpSchemes() {
  // ok: cleartext-communication-http-usage
  final fileUri = Uri.parse('file:///path/to/local/file.txt');

  // ok: cleartext-communication-http-usage
  final mailUri = Uri.parse('mailto:user@example.com');

  // ok: cleartext-communication-http-usage
  final telUri = Uri.parse('tel:+1234567890');

  // ok: cleartext-communication-http-usage
  final ftpUri = Uri.parse('ftp://files.example.com/data');
}

void testStringContext() {
  // ok: cleartext-communication-http-usage
  final docLink = 'http://docs.example.com';

  // ok: cleartext-communication-http-usage
  final exampleText = 'Visit http://example.com for more info';

  // ok: cleartext-communication-http-usage
  final regexPattern = r'^https?://';
}

// =============================================================================
// Валидация и санитизация
// =============================================================================

Future<void> testValidation(String inputUrl, String userPath) async {
  // ok: cleartext-communication-http-usage
  final validatedUri = Uri.parse(inputUrl);
  if (validatedUri.scheme != 'https') throw ArgumentError('Only HTTPS allowed');

  // ok: cleartext-communication-http-usage
  final sanitizedUrl = 'https://api.example.com/${userPath.replaceAll(RegExp(r'[^a-zA-Z0-9/_-]'), '')}';
}

class SecurityHelper {
  // ok: cleartext-communication-http-usage
  static String enforceHttps(String url) => url.replaceFirst(RegExp(r'^http://'), 'https://');

  // ok: cleartext-communication-http-usage
  static String getSafeUrl(String? customUrl) => 
      customUrl?.startsWith('http://') == true ? 'https://api.example.com' : customUrl ?? 'https://api.example.com';
}

// =============================================================================
// Граничные случаи
// =============================================================================

Future<void> testEdgeCases() async {
  // ruleid: cleartext-communication-http-usage
  final httpPort = await http.get(Uri.parse('http://api.example.com:8080/data'));

  // ok: cleartext-communication-http-usage
  final httpsPort = await http.get(Uri.parse('https://api.example.com:8443/data'));

  // ok: cleartext-communication-http-usage
  final localPort = await http.get(Uri.parse('http://localhost:3000/api'));

  // ruleid: cleartext-communication-http-usage
  final ipv6Http = await http.get(Uri.parse('http://[2001:db8::1]:8080/api'));

  // ok: cleartext-communication-http-usage
  final ipv6Https = await http.get(Uri.parse('https://[2001:db8::1]:8443/api'));

  // ok: cleartext-communication-http-usage
  final ipv6Local = await http.get(Uri.parse('http://[::1]:8080/api'));

  // ruleid: cleartext-communication-http-usage
  final encodedHttp = Uri.parse('http://api.example.com/search?q=hello%20world');

  // ok: cleartext-communication-http-usage
  final encodedHttps = Uri.parse('https://api.example.com/search?q=hello%20world');

  // ruleid: cleartext-communication-http-usage
  final absoluteHttp = await http.get(Uri.parse('http://cdn.example.com/assets/image.png'));

  // ok: cleartext-communication-http-usage
  final relativePath = await http.get(Uri.parse('/api/users'));

  // ok: cleartext-communication-http-usage
  final protoRelative = await http.get(Uri.parse('//cdn.example.com/script.js'));
}

// =============================================================================
// Асинхронные паттерны
// =============================================================================

Stream<http.Response> testStreamPattern() {
  // ruleid: cleartext-communication-http-usage
  return Stream.fromFuture(http.get(Uri.parse('http://stream.example.com/data'))).asBroadcastStream();
}

Future<void> testIsolatePattern() async {
  // ruleid: cleartext-communication-http-usage
  final isolateReq = await http.get(Uri.parse('http://api.example.com/isolate-data'));
}

Stream<http.Response> testSecureStream() async* {
  // ok: cleartext-communication-http-usage
  yield await http.get(Uri.parse('https://stream.example.com/data'));
}

// =============================================================================
// Интерцепторы
// =============================================================================

Future<void> testInterceptors() async {
  final dio = Dio();
  dio.interceptors.add(InterceptorsWrapper(
    onRequest: (options, handler) => handler.next(options),
  ));
  
  // ruleid: cleartext-communication-http-usage
  await dio.get('http://api.example.com/data');
}

Future<void> testHttpsEnforcingInterceptor() async {
  final dio = Dio();
  dio.interceptors.add(InterceptorsWrapper(
    onRequest: (options, handler) {
      // ok: cleartext-communication-http-usage
      if (options.uri.scheme == 'http' && !options.uri.host.contains('localhost')) {
        options.uri = options.uri.replace(scheme: 'https');
      }
      return handler.next(options);
    },
  ));
  await dio.get('http://api.example.com/data');
}

// =============================================================================
// Комплексные сценарии
// =============================================================================

class AuthService {
  // ruleid: cleartext-communication-http-usage
  Future<bool> login(String username, String password) async {
    final response = await http.post(
      Uri.parse('http://auth.example.com/login'),
      body: {'username': username, 'password': password},
    );
    return response.statusCode == 200;
  }
}

Future<void> testFileUpload() async {
  // ruleid: cleartext-communication-http-usage
  final uploadReq = http.MultipartRequest('POST', Uri.parse('http://upload.example.com/docs'));
  uploadReq.files.add(await http.MultipartFile.fromPath('doc', 'sensitive.pdf'));
  await uploadReq.send();
}

Stream<Map<String, dynamic>> testPolling() async* {
  while (true) {
    // ruleid: cleartext-communication-http-usage
    final response = await http.get(Uri.parse('http://poll.example.com/updates'));
    if (response.statusCode == 200) {
      yield jsonDecode(response.body);
    }
    await Future.delayed(const Duration(seconds: 30));
  }
}

Stream<Map<String, dynamic>> testSecurePolling() async* {
  while (true) {
    // ok: cleartext-communication-http-usage
    final response = await http.get(Uri.parse('https://poll.example.com/updates'));
    if (response.statusCode == 200) {
      yield jsonDecode(response.body);
    }
    await Future.delayed(const Duration(seconds: 30));
  }
}

// =============================================================================
// Тесты точности правила
// =============================================================================

Future<void> testRegexAccuracy() async {
  // ruleid: cleartext-communication-http-usage
  final test1 = Uri.parse('http://a.com');

  // ruleid: cleartext-communication-http-usage
  final test2 = Uri.parse('HTTP://B.COM');

  // ruleid: cleartext-communication-http-usage
  final test3 = Uri.parse('Http://C.com');

  // ruleid: cleartext-communication-http-usage
  final test4 = Uri.http('d.com', '/path');

  // ruleid: cleartext-communication-http-usage
  final test5 = Uri(scheme: 'http', host: 'e.com');

  // ok: cleartext-communication-http-usage
  final httpsTest1 = Uri.parse('https://a.com');

  // ok: cleartext-communication-http-usage
  final httpsTest2 = Uri.parse('HTTPS://B.COM');

  // ok: cleartext-communication-http-usage
  final httpsTest3 = Uri.https('d.com', '/path');

  // ok: cleartext-communication-http-usage
  final httpsTest4 = Uri(scheme: 'https', host: 'e.com');
}

// =============================================================================
// Контекстный анализ
// =============================================================================

void testStringNotRequest() {
  // ok: cleartext-communication-http-usage
  final message = 'Please visit http://example.com for help';

  // ok: cleartext-communication-http-usage
  final regex = RegExp(r'^https?://');

  // ok: cleartext-communication-http-usage
  final todo = 'TODO: migrate from http:// to https://';
}

Future<void> testActualRequest() async {
  // ruleid: cleartext-communication-http-usage
  final actualReq = await http.get(Uri.parse('http://example.com/api'));
}

class UrlValidator {
  // ok: cleartext-communication-http-usage
  static bool isValidUrl(String url) {
    try {
      return Uri.parse(url).isAbsolute;
    } catch (e) {
      return false;
    }
  }
}

Future<void> testValidatedButInsecure(String url) async {
  // ruleid: cleartext-communication-http-usage
  if (UrlValidator.isValidUrl(url)) await http.get(Uri.parse(url));
}

// =============================================================================
// Flutter-specific паттерны
// =============================================================================

Widget testNetworkImage() {
  // ruleid: cleartext-communication-http-usage
  return Image.network('http://cdn.example.com/image.png');
}

Widget testSecureNetworkImage() {
  // ok: cleartext-communication-http-usage
  return Image.network('https://cdn.example.com/image.png');
}

Widget testAssetImage() {
  // ok: cleartext-communication-http-usage
  return Image.asset('assets/images/local.png');
}

Future<void> testBadCertificateCallback() async {
  // ruleid: cleartext-communication-http-usage
  final badCertClient = HttpClient()..badCertificateCallback = (c, h, p) => true;
  final badCertReq = await badCertClient.getUrl(Uri.parse('http://api.example.com/data'));
}

Future<void> testGoodCertificateCallback() async {
  // ok: cleartext-communication-http-usage
  final goodCertClient = HttpClient()..badCertificateCallback = (c, h, p) => false;
  final goodCertReq = await goodCertClient.getUrl(Uri.parse('https://api.example.com/data'));
}

// =============================================================================
// Миграционные паттерны
// =============================================================================

Future<void> testMigration(String legacyHttpUrl) async {
  // ok: cleartext-communication-http-usage
  final migratedUrl = legacyHttpUrl.replaceFirst(
    RegExp(r'^http://(?!localhost|127\.0\.0\.1|\[::1\])'), 
    'https://',
  );
  await http.get(Uri.parse(migratedUrl));
}

class MigrationHelper {
  // ok: cleartext-communication-http-usage
  static String ensureHttps(String url) {
    if (url.startsWith('http://')) {
      final uri = Uri.parse(url);
      if (['localhost', '127.0.0.1', '::1'].contains(uri.host)) return url;
      return uri.replace(scheme: 'https').toString();
    }
    return url;
  }
}

Future<void> testIncompleteMigration(String url) async {
  // ruleid: cleartext-communication-http-usage
  if (!url.contains('localhost')) await http.get(Uri.parse(url));
}

// =============================================================================
// Вспомогательные функции
// =============================================================================

Future<Map<String, dynamic>> _loadConfig() async => {'base_url': 'http://api.example.com'};

Future<Map<String, String>> _getCredentials() async => {'username': 'user', 'password': 'secret'};

Map<String, dynamic> _sanitizeResponse(Map<String, dynamic> r) {
  r.remove('password');
  r.remove('token');
  return r;
}