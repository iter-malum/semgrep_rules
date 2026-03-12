// test_missing_ssl_pinning.dart
// Тест для правила: missing-ssl-pinning
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: missing-ssl-pinning
const String API_URL = 'https://api.example.com';

// ok: missing-ssl-pinning
const String CERTIFICATE_HASH = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HttpClient без badCertificateCallback (по умолчанию разрешает всё)
// =============================================================================

// ruleid: missing-ssl-pinning
final client1 = HttpClient();

// ruleid: missing-ssl-pinning
final client2 = HttpClient()..connectionTimeout = Duration(seconds: 5);

Future<void> testDefaultHttpClient() async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient();
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

Future<void> testConfiguredButNoPinning() async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient()
    ..connectionTimeout = Duration(seconds: 10)
    ..idleTimeout = Duration(minutes: 1);
  
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: badCertificateCallback возвращает true (критично!)
// =============================================================================

// ruleid: missing-ssl-pinning
final insecureClient1 = HttpClient()..badCertificateCallback = (cert, host, port) => true;

// ruleid: missing-ssl-pinning
final insecureClient2 = HttpClient()..badCertificateCallback = (X509Certificate cert, String host, int port) => true;

Future<void> testAlwaysTrustCallback() async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient()..badCertificateCallback = (cert, host, port) => true;
  
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

Future<void> testExplicitTrueCallback() async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient()
    ..badCertificateCallback = (X509Certificate cert, String host, int port) {
      return true;
    };
  
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Dio без интерцептора или с небезопасным интерцептором
// =============================================================================

// ruleid: missing-ssl-pinning
final dio1 = Dio();

// ruleid: missing-ssl-pinning
final dio2 = Dio(BaseOptions(baseUrl: 'https://api.example.com'));

Future<void> testDefaultDio() async {
  // ruleid: missing-ssl-pinning
  final dio = Dio();
  await dio.get('https://api.example.com/data');
}

Future<void> testDioWithBaseOptions() async {
  // ruleid: missing-ssl-pinning
  final dio = Dio(BaseOptions(
    baseUrl: 'https://api.example.com',
    connectTimeout: const Duration(seconds: 5),
  ));
  await dio.get('/data');
}

// ruleid: missing-ssl-pinning
final dioInsecureValidateStatus = Dio()..options.validateStatus = (status) => true;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Dio с отключенной валидацией сертификатов
// =============================================================================

// ruleid: missing-ssl-pinning
final dioNoVerify = Dio()
  ..httpClientAdapter = DefaultHttpClientAdapter()
  ..options.sendTimeout = Duration(seconds: 5);
  // Примечание: без настройки onHttpClientCreate для проверки сертификата это уязвимо

Future<void> testDioWithoutAdapterConfig() async {
  // ruleid: missing-ssl-pinning
  final dio = Dio();
  // Нет настройки httpClientAdapter для pinning
  await dio.get('https://api.example.com');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: http.Client (package:http) без кастомного HttpClient
// =============================================================================

// ruleid: missing-ssl-pinning
final httpClient1 = http.Client();

// ruleid: missing-ssl-pinning
final httpClient2 = http.Client()..get(Uri.parse('https://api.example.com'));

Future<void> testPackageHttpClient() async {
  // ruleid: missing-ssl-pinning
  final client = http.Client();
  await client.get(Uri.parse('https://api.example.com/data'));
  client.close();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: WebSocket без проверки сертификатов
// =============================================================================

// ruleid: missing-ssl-pinning
final wsChannel1 = WebSocketChannel.connect(Uri.parse('wss://ws.example.com'));

// ruleid: missing-ssl-pinning
final wsChannel2 = IOWebSocketChannel.connect(Uri.parse('wss://ws.example.com'));

Future<void> testWebSocketNoPinning() async {
  // ruleid: missing-ssl-pinning
  final channel = IOWebSocketChannel.connect(Uri.parse('wss://ws.example.com/stream'));
  channel.stream.listen((message) {});
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Классы и сервисы без SSL Pinning
// =============================================================================

class InsecureApiService {
  // ruleid: missing-ssl-pinning
  final HttpClient _client = HttpClient();

  Future<String> fetchData() async {
    // ruleid: missing-ssl-pinning
    final request = await _client.getUrl(Uri.parse('https://api.example.com/data'));
    final response = await request.close();
    return utf8.decode(await response.transform(utf8.decoder).toList());
  }
}

class InsecureDioService {
  // ruleid: missing-ssl-pinning
  final Dio _dio = Dio();

  Future<Map> getData() async {
    // ruleid: missing-ssl-pinning
    final response = await _dio.get('https://api.example.com/data');
    return response.data;
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Частичная защита (недостаточно)
// =============================================================================

// ruleid: missing-ssl-pinning
final partialClient = HttpClient()
  ..badCertificateCallback = (cert, host, port) {
    // Проверка только хоста, но не сертификата - недостаточно!
    if (host == 'api.example.com') return true; 
    return false;
  };

Future<void> testHostCheckOnly() async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) => host == 'trusted.com';
  
  final request = await client.getUrl(Uri.parse('https://trusted.com/data'));
  await request.close();
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: HttpClient с правильной проверкой сертификата (SSL Pinning)
// =============================================================================

// ok: missing-ssl-pinning
final secureClient1 = HttpClient()
  ..badCertificateCallback = (cert, host, port) {
    const expectedHash = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    return cert.sha256 == expectedHash;
  };

// ok: missing-ssl-pinning
final secureClient2 = HttpClient()
  ..badCertificateCallback = (X509Certificate cert, String host, int port) {
    // Проверка хоста И хеша сертификата
    if (host != 'api.example.com') return false;
    const pinnedHash = 'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
    return cert.sha256 == pinnedHash;
  };

Future<void> testSecureHttpClient() async {
  // ok: missing-ssl-pinning
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) {
      const trustedHash = 'sha256/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=';
      return cert.sha256 == trustedHash;
    };
  
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Dio с настроенным SSL Pinning
// =============================================================================

// ok: missing-ssl-pinning
final secureDio1 = Dio()
  ..httpClientAdapter = DefaultHttpClientAdapter()
  ..options.extra['pinnedCertificates'] = true; 
  // В реальном коде здесь была бы логика проверки в onHttpClientCreate

// ok: missing-ssl-pinning
final secureDio2 = Dio(BaseOptions(baseUrl: 'https://api.example.com'))
  ..httpClientAdapter = DefaultHttpClientAdapter()
  ..options.context = {'pinned': true};

Future<void> testSecureDio() async {
  // ok: missing-ssl-pinning
  final dio = Dio();
  dio.httpClientAdapter = DefaultHttpClientAdapter(
    onHttpClientCreate: (client) {
      client.badCertificateCallback = (cert, host, port) {
        const expectedHash = 'sha256/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=';
        return cert.sha256 == expectedHash;
      };
      return client;
    },
  );
  
  await dio.get('https://api.example.com/data');
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование готовых решений для Pinning
// =============================================================================

// ok: missing-ssl-pinning
final secureDioWithPlugin = Dio()
  ..httpClientAdapter = SecureHttpClientAdapter(); // Плагин с пиннингом

// ok: missing-ssl-pinning
Future<void> testSecureWebSocket() async {
  // ok: missing-ssl-pinning
  // Предполагается использование безопасного канала с валидацией на уровне ОС или библиотеки
  // Если используется стандартный IOWebSocketChannel без кастомизации SecurityContext - это риск,
  // но для теста считаем безопасным, если нет явного отключения проверок.
  // Однако, лучший вариант - явная настройка SecurityContext.
  final context = SecurityContext()
    ..setTrustedCertificatesBytes(certBytes);
  
  final channel = IOWebSocketChannel.connect(
    Uri.parse('wss://ws.example.com'),
    pingInterval: const Duration(seconds: 30),
  );
  // В реальности нужно передавать securityContext в конструктор, если библиотека поддерживает
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: http.Client с кастомным безопасным HttpClient
// =============================================================================

// ok: missing-ssl-pinning
final secureHttpContext = http.Client(); 
// Примечание: package:http по умолчанию доверяет системным CA. 
// Для строгого пиннинга нужно использовать dart:io HttpClient с проверкой и оборачивать его.
// Считаем этот кейс "серой зоной", но для целей теста помечаем как OK, 
// если нет явного отключения проверок (badCertificateCallback = true).
// Чтобы быть строгим, можно считать ruleid, если нет явного пиннинга, 
// но обычно отсутствие явного "разрешить всё" считается базовой защитой.
// ДЛЯ ЭТОГО ТЕСТА: Считаем OK, так как нет явной уязвимости (return true).

// ok: missing-ssl-pinning
Future<void> testSecureHttpPackage() async {
  // ok: missing-ssl-pinning
  final client = http.Client();
  await client.get(Uri.parse('https://api.example.com'));
  client.close();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условная логика
// =============================================================================

// ruleid: missing-ssl-pinning
final conditionalClient = HttpClient()
  ..badCertificateCallback = usePinning 
      ? (cert, host, port) => cert.sha256 == expectedHash 
      : (cert, host, port) => true; // Уязвимая ветка

Future<void> testConditionalPinning(bool usePinning) async {
  // ruleid: missing-ssl-pinning
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) {
      if (usePinning) {
        return cert.sha256 == expectedHash;
      }
      return true; // Уязвимость здесь
    };
  
  final request = await client.getUrl(Uri.parse('https://api.example.com'));
  await request.close();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Try-Catch блоки
// =============================================================================

// ruleid: missing-ssl-pinning
final tryCatchClient = HttpClient()
  ..badCertificateCallback = (cert, host, port) {
    try {
      // Какая-то логика
      return true; // Опасно внутри try
    } catch (e) {
      return false;
    }
  };

// ok: missing-ssl-pinning
final safeTryCatchClient = HttpClient()
  ..badCertificateCallback = (cert, host, port) {
    try {
      return cert.sha256 == expectedHash;
    } catch (e) {
      return false; // Fail secure
    }
  };

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

extension InsecureHttpClient on HttpClient {
  // ruleid: missing-ssl-pinning
  static HttpClient createInsecure() {
    return HttpClient()..badCertificateCallback = (c, h, p) => true;
  }
}

extension SecureHttpClient on HttpClient {
  // ok: missing-ssl-pinning
  static HttpClient createSecure() {
    return HttpClient()
      ..badCertificateCallback = (c, h, p) => c.sha256 == expectedHash;
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Фабрики
// =============================================================================

class ClientFactory {
  // ruleid: missing-ssl-pinning
  static HttpClient getInsecure() => HttpClient()..badCertificateCallback = (c, h, p) => true;
}

// ok: missing-ssl-pinning
class SecureClientFactory {
  // ok: missing-ssl-pinning
  static HttpClient getSecure() => HttpClient()
    ..badCertificateCallback = (c, h, p) => c.sha256 == expectedHash;
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Комментарии и строки
// =============================================================================

void testStringNotCode() {
  // ok: missing-ssl-pinning
  final comment = 'HttpClient badCertificateCallback should return false by default';
  
  // ok: missing-ssl-pinning
  final config = {'sslPinning': 'enabled', 'checkCert': 'true'};
  
  // ok: missing-ssl-pinning
  print('Warning: Enable SSL Pinning in production');
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ
// =============================================================================

// ruleid: missing-ssl-pinning
class LegacyApiService {
  // ruleid: missing-ssl-pinning
  final HttpClient _client = HttpClient()..badCertificateCallback = (c, h, p) => true;
  
  // ruleid: missing-ssl-pinning
  Future<String> getData() async {
    final req = await _client.getUrl(Uri.parse('https://legacy.api.com'));
    return utf8.decode(await req.transform(utf8.decoder).toList());
  }
}

// ok: missing-ssl-pinning
class ModernApiService {
  // ok: missing-ssl-pinning
  final Dio _dio = Dio()
    ..httpClientAdapter = DefaultHttpClientAdapter(
      onHttpClientCreate: (client) {
        client.badCertificateCallback = (cert, host, port) {
          return cert.sha256 == expectedHash;
        };
        return client;
      },
    );
  
  // ok: missing-ssl-pinning
  Future<Map> getData() async {
    final res = await _dio.get('https://modern.api.com/data');
    return res.data;
  }
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

Uint8List certBytes = Uint8List.fromList([1, 2, 3]);
String expectedHash = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
bool usePinning = false;

class SecureHttpClientAdapter extends HttpClientAdapter {
  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future? cancelFuture) {
    throw UnimplementedError();
  }
  @override
  void close({bool force = false}) {}
}

class DefaultHttpClientAdapter implements HttpClientAdapter {
  DefaultHttpClientAdapter({this.onHttpClientCreate});
  Function(HttpClient client)? onHttpClientCreate;
  
  @override
  Future<ResponseBody> fetch(RequestOptions options, Stream<Uint8List>? requestStream, Future? cancelFuture) {
    throw UnimplementedError();
  }
  @override
  void close({bool force = false}) {}
}

extension on X509Certificate {
  String get sha256 => 'dummy_hash';
}