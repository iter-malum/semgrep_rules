// test_ssrf.dart
// Тест для правил SSRF:
// - ssrf-http-client: Server-Side Request Forgery через HTTP клиенты
// - ssrf-image-network: SSRF через Image.network виджет
// - ssrf-websocket: SSRF через WebSocket соединения
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';
import 'dart:convert';
import 'dart:io';

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

bool _isInternalIp(String host) {
  try {
    final ip = InternetAddress(host);
    return ip.isPrivate;
  } catch (_) {
    return false;
  }
}

bool _isWhitelistedDomain(String url) {
  const whitelist = ['api.example.com', 'images.example.com'];
  try {
    final uri = Uri.parse(url);
    return whitelist.contains(uri.host);
  } catch (_) {
    return false;
  }
}

String _sanitizeUrl(String url) {
  if (_isWhitelistedDomain(url)) {
    return url;
  }
  return 'https://api.example.com';
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через HTTP Client
// =============================================================================

void testHttpGet(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(userUrl));
}

void testHttpPost(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.post(
    Uri.parse(userUrl),
    body: {'key': 'value'},
  );
}

void testHttpPut(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.put(Uri.parse(userUrl));
}

void testHttpDelete(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.delete(Uri.parse(userUrl));
}

void testHttpPatch(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.patch(Uri.parse(userUrl));
}

void testHttpHead(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.head(Uri.parse(userUrl));
}

void testHttpWithHeaders(String userUrl) async {
  // ruleid: flutter-ssrf
  final response = await http.get(
    Uri.parse(userUrl),
    headers: {'Authorization': 'Bearer token'},
  );
}

void testHttpWithInterpolation(String baseUrl, String path) async {
  String url = '$baseUrl/$path';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testHttpWithConcatenation(String host, String endpoint) async {
  String url = 'https://' + host + '/' + endpoint;
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testHttpFromApi(String apiResponse) async {
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(data['url']));
}

void testHttpFromDatabase(String dbResult) async {
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(dbResult));
}

void testHttpFromUserInput(String userInput) async {
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(userInput));
}

void testHttpWithCondition(String url) async {
  if (url.isNotEmpty) {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(url));
  }
}

void testHttpInCallback(String url) {
  Future.delayed(Duration(seconds: 1), () async {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(url));
  });
}

void testHttpWithPort(String host, int port) async {
  String url = 'http://$host:$port/api';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testHttpWithQueryParams(String baseUrl, Map<String, String> params) async {
  String query = params.entries.map((e) => '${e.key}=${e.value}').join('&');
  String url = '$baseUrl?$query';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testHttpClientRequest(String userUrl) async {
  final client = http.Client();
  // ruleid: flutter-ssrf
  final response = await client.get(Uri.parse(userUrl));
  client.close();
}

void testHttpClientMultiple(String url1, String url2) async {
  final client = http.Client();
  // ruleid: flutter-ssrf
  await client.get(Uri.parse(url1));
  // ruleid: flutter-ssrf
  await client.post(Uri.parse(url2));
  client.close();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через Image.network
// =============================================================================

Widget testImageNetwork(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(imageUrl);
}

Widget testImageNetworkWithHeaders(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(
    imageUrl,
    headers: {'Authorization': 'Bearer token'},
  );
}

Widget testImageNetworkWithScale(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(
    imageUrl,
    scale: 2.0,
  );
}

Widget testImageNetworkWithFrameBuilder(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(
    imageUrl,
    frameBuilder: (context, child, frame, loaded) {
      return child;
    },
  );
}

Widget testImageNetworkWithLoadingBuilder(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(
    imageUrl,
    loadingBuilder: (context, child, progress) {
      return child;
    },
  );
}

Widget testImageNetworkWithErrorBuilder(String imageUrl) {
  // ruleid: flutter-ssrf
  return Image.network(
    imageUrl,
    errorBuilder: (context, error, stack) {
      return Text('Error');
    },
  );
}

Widget testImageNetworkWithInterpolation(String baseUrl, String path) {
  String url = '$baseUrl/images/$path';
  // ruleid: flutter-ssrf
  return Image.network(url);
}

Widget testImageNetworkWithConcatenation(String host, String image) {
  String url = 'https://' + host + '/images/' + image;
  // ruleid: flutter-ssrf
  return Image.network(url);
}

Widget testImageNetworkFromApi(String apiResponse) {
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-ssrf
  return Image.network(data['image_url']);
}

Widget testImageNetworkFromDatabase(String dbResult) {
  // ruleid: flutter-ssrf
  return Image.network(dbResult);
}

Widget testImageNetworkFromUserInput(String userInput) {
  // ruleid: flutter-ssrf
  return Image.network(userInput);
}

Widget testImageNetworkWithCondition(bool show, String url) {
  if (show) {
    // ruleid: flutter-ssrf
    return Image.network(url);
  }
  return Container();
}

Widget testImageNetworkInList(List<String> urls) {
  return Column(
    children: urls.map((url) {
      // ruleid: flutter-ssrf
      return Image.network(url);
    }).toList(),
  );
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через WebSocket
// =============================================================================

void testWebSocketConnect(String wsUrl) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
}

void testWebSocketSecure(String wssUrl) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(wssUrl));
}

void testWebSocketWithInterpolation(String host, int port) {
  String url = 'ws://$host:$port/socket';
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(url));
}

void testWebSocketWithConcatenation(String host, String path) {
  String url = 'ws://' + host + '/' + path;
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(url));
}

void testWebSocketFromApi(String apiResponse) {
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(data['socket_url']));
}

void testWebSocketFromDatabase(String dbResult) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(dbResult));
}

void testWebSocketFromUserInput(String userInput) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(userInput));
}

void testWebSocketWithCondition(String url) {
  if (url.isNotEmpty) {
    // ruleid: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(url));
  }
}

void testWebSocketSendReceive(String url, String message) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(url));
  channel.sink.add(message);
  channel.stream.listen((data) {
    print(data);
  });
}

void testWebSocketWithPing(String url) {
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(url));
  channel.sink.add('ping');
}

void testWebSocketWithPort(String host, int port) {
  String url = 'ws://$host:$port';
  // ruleid: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse(url));
}

void testWebSocketInCallback(String url) {
  Future.delayed(Duration(seconds: 1), () {
    // ruleid: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(url));
  });
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF в StatefulWidget
// =============================================================================

class SSRFStatefulWidget extends StatefulWidget {
  @override
  _SSRFStatefulWidgetState createState() => _SSRFStatefulWidgetState();
}

class _SSRFStatefulWidgetState extends State<SSRFStatefulWidget> {
  String _userUrl = '';
  String _imageUrl = '';
  String _wsUrl = '';
  final TextEditingController _controller = TextEditingController();

  void _fetchData() async {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(_userUrl));
    print(response.body);
  }

  void _loadImage() {
    setState(() {});
  }

  void _connectWebSocket() {
    // ruleid: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(_wsUrl));
    channel.stream.listen((data) {
      print(data);
    });
  }

  void _onUrlChanged(String value) {
    setState(() {
      _userUrl = value;
    });
  }

  void _onImageUrlChanged(String value) {
    setState(() {
      _imageUrl = value;
    });
  }

  void _onWebSocketUrlChanged(String value) {
    setState(() {
      _wsUrl = value;
    });
  }

  void _onSubmit() async {
    // ruleid: flutter-ssrf
    await http.get(Uri.parse(_controller.text));
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: _controller,
          onChanged: _onUrlChanged,
          onSubmitted: (_) => _onSubmit(),
        ),
        TextField(
          onChanged: _onImageUrlChanged,
          decoration: InputDecoration(labelText: 'Image URL'),
        ),
        TextField(
          onChanged: _onWebSocketUrlChanged,
          decoration: InputDecoration(labelText: 'WebSocket URL'),
        ),
        ElevatedButton(
          onPressed: _fetchData,
          child: Text('Fetch Data'),
        ),
        ElevatedButton(
          onPressed: _connectWebSocket,
          child: Text('Connect WebSocket'),
        ),
        // ruleid: flutter-ssrf
        Image.network(_imageUrl),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через DecorationImage
// =============================================================================

Widget testDecorationImage(String imageUrl) {
  return Container(
    decoration: BoxDecoration(
      image: DecorationImage(
        // ruleid: flutter-ssrf
        image: NetworkImage(imageUrl),
        fit: BoxFit.cover,
      ),
    ),
  );
}

Widget testDecorationImageWithHeaders(String imageUrl) {
  return Container(
    decoration: BoxDecoration(
      image: DecorationImage(
        // ruleid: flutter-ssrf
        image: NetworkImage(imageUrl, headers: {'Auth': 'token'}),
        fit: BoxFit.cover,
      ),
    ),
  );
}

Widget testDecorationImageInContainer(String imageUrl) {
  // ruleid: flutter-ssrf
  return Container(
    decoration: BoxDecoration(
      image: DecorationImage(
        image: NetworkImage(imageUrl),
      ),
    ),
  );
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через FadeInImage
// =============================================================================

Widget testFadeInImage(String imageUrl) {
  // ruleid: flutter-ssrf
  return FadeInImage(
    placeholder: AssetImage('assets/placeholder.png'),
    image: NetworkImage(imageUrl),
  );
}

Widget testFadeInImageWithMemory(String imageUrl) {
  // ruleid: flutter-ssrf
  return FadeInImage(
    placeholder: MemoryImage(Uint8List(0)),
    image: NetworkImage(imageUrl),
  );
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF в циклах и списках
// =============================================================================

class SSRFInLists extends StatelessWidget {
  final List<String> httpUrls;
  final List<String> imageUrls;
  final List<String> wsUrls;

  SSRFInLists({
    required this.httpUrls,
    required this.imageUrls,
    required this.wsUrls,
  });

  void fetchAllUrls() async {
    for (var url in httpUrls) {
      // ruleid: flutter-ssrf
      await http.get(Uri.parse(url));
    }
  }

  void connectAllWebSockets() {
    for (var url in wsUrls) {
      // ruleid: flutter-ssrf
      WebSocketChannel.connect(Uri.parse(url));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        ...imageUrls.map((url) => 
          // ruleid: flutter-ssrf
          Image.network(url)
        ),
        ...httpUrls.map((url) => 
          FutureBuilder(
            future: http.get(Uri.parse(url)),
            builder: (context, snapshot) {
              return Text(snapshot.data?.body ?? '');
            },
          )
        ),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF с внутренними IP
// =============================================================================

void testInternalIP(String ip) async {
  String url = 'http://$ip:8080/admin';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testLocalhost() async {
  String url = 'http://localhost:8080/api';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testLoopback(String path) async {
  String url = 'http://127.0.0.1:3000/$path';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testPrivateRange(String ip, int port) async {
  String url = 'http://$ip:$port/internal';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SSRF через различные протоколы
// =============================================================================

void testFileProtocol(String path) async {
  String url = 'file:///etc/passwd';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testFtpProtocol(String host, String path) async {
  String url = 'ftp://$host/$path';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testGopherProtocol(String host, int port) async {
  String url = 'gopher://$host:$port/_data';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

void testDictProtocol(String host) async {
  String url = 'dict://$host:2628/';
  // ruleid: flutter-ssrf
  final response = await http.get(Uri.parse(url));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные HTTP запросы
// =============================================================================

void safeHttpGetWithValidation(String userUrl) async {
  if (_isWhitelistedDomain(userUrl)) {
    // ok: flutter-ssrf
    final response = await http.get(Uri.parse(userUrl));
  }
}

void safeHttpGetWithWhitelist(String userUrl) async {
  const whitelist = ['api.example.com', 'data.example.com'];
  try {
    final uri = Uri.parse(userUrl);
    if (whitelist.contains(uri.host)) {
      // ok: flutter-ssrf
      final response = await http.get(uri);
    }
  } catch (_) {}
}

void safeHttpGetWithIpCheck(String userUrl) async {
  try {
    final uri = Uri.parse(userUrl);
    if (!_isInternalIp(uri.host)) {
      // ok: flutter-ssrf
      final response = await http.get(uri);
    }
  } catch (_) {}
}

void safeHttpGetWithSanitization(String userUrl) async {
  String safeUrl = _sanitizeUrl(userUrl);
  // ok: flutter-ssrf
  final response = await http.get(Uri.parse(safeUrl));
}

void safeHttpGetWithSchemeCheck(String userUrl) async {
  try {
    final uri = Uri.parse(userUrl);
    if (uri.scheme == 'https' && uri.host == 'api.example.com') {
      // ok: flutter-ssrf
      final response = await http.get(uri);
    }
  } catch (_) {}
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные Image.network
// =============================================================================

Widget safeImageNetwork(String imageUrl) {
  if (_isWhitelistedDomain(imageUrl)) {
    // ok: flutter-ssrf
    return Image.network(imageUrl);
  }
  return Container();
}

Widget safeImageNetworkWithValidation(String imageUrl) {
  try {
    final uri = Uri.parse(imageUrl);
    if (uri.scheme == 'https' && uri.host == 'images.example.com') {
      // ok: flutter-ssrf
      return Image.network(imageUrl);
    }
  } catch (_) {}
  return Container();
}

Widget safeImageNetworkWithSanitization(String imageUrl) {
  String safeUrl = _sanitizeUrl(imageUrl);
  // ok: flutter-ssrf
  return Image.network(safeUrl);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные WebSocket
// =============================================================================

void safeWebSocketWithValidation(String wsUrl) {
  if (_isWhitelistedDomain(wsUrl)) {
    // ok: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(wsUrl));
  }
}

void safeWebSocketWithWhitelist(String wsUrl) {
  const whitelist = ['ws.example.com', 'socket.example.com'];
  try {
    final uri = Uri.parse(wsUrl);
    if (whitelist.contains(uri.host)) {
      // ok: flutter-ssrf
      final channel = WebSocketChannel.connect(uri);
    }
  } catch (_) {}
}

void safeWebSocketWithIpCheck(String wsUrl) {
  try {
    final uri = Uri.parse(wsUrl);
    if (!_isInternalIp(uri.host)) {
      // ok: flutter-ssrf
      final channel = WebSocketChannel.connect(uri);
    }
  } catch (_) {}
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Статические URL
// =============================================================================

void staticHttpGet() async {
  // ok: flutter-ssrf
  final response = await http.get(Uri.parse('https://api.example.com/data'));
}

Widget staticImageNetwork() {
  // ok: flutter-ssrf
  return Image.network('https://images.example.com/photo.jpg');
}

void staticWebSocket() {
  // ok: flutter-ssrf
  final channel = WebSocketChannel.connect(Uri.parse('wss://socket.example.com'));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Локальные изображения
// =============================================================================

Widget localAssetImage() {
  // ok: flutter-ssrf
  return Image.asset('assets/image.png');
}

Widget localFileImage() {
  // ok: flutter-ssrf
  return Image.file(File('/local/image.jpg'));
}

Widget memoryImage() {
  // ok: flutter-ssrf
  return Image.memory(Uint8List(0));
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Неполная валидация
// =============================================================================

void partialValidationHttp(String url) async {
  if (url.startsWith('https://')) {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(url));
  }
}

void partialDomainCheckHttp(String url) async {
  if (url.contains('api.')) {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(url));
  }
}

Widget partialValidationImage(String url) {
  if (url.endsWith('.jpg') || url.endsWith('.png')) {
    // ruleid: flutter-ssrf
    return Image.network(url);
  }
  return Container();
}

void partialValidationWebSocket(String url) {
  if (url.startsWith('wss://')) {
    // ruleid: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(url));
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условные запросы
// =============================================================================

void conditionalHttp(String url, bool isAdmin) async {
  if (isAdmin) {
    // ruleid: flutter-ssrf
    final response = await http.get(Uri.parse(url));
  }
}

Widget conditionalImage(String url, bool isAuthenticated) {
  if (isAuthenticated) {
    // ruleid: flutter-ssrf
    return Image.network(url);
  }
  return Container();
}

void conditionalWebSocket(String url, bool isUser) {
  if (isUser) {
    // ruleid: flutter-ssrf
    final channel = WebSocketChannel.connect(Uri.parse(url));
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Обход через редиректы
// =============================================================================

void followRedirects(String url) async {
  final client = http.Client();
  // ruleid: flutter-ssrf
  final response = await client.get(
    Uri.parse(url),
    headers: {'X-Forwarded-Host': 'internal-server'},
  );
  client.close();
}

void withRedirects(String url) async {
  // ruleid: flutter-ssrf
  final response = await http.get(
    Uri.parse(url),
    headers: {'Host': 'localhost:8080'},
  );
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ПЕРЕМЕННЫЕ
// =============================================================================

String userProvidedUrl = 'http://169.254.169.254/latest/meta-data/';
String userImageUrl = 'http://localhost:8080/image.jpg';
String userWebSocketUrl = 'ws://internal-server:3000/socket';
String apiResponse = '{"url": "http://192.168.1.1/admin"}';
String internalIp = '10.0.0.1';
int internalPort = 8080;