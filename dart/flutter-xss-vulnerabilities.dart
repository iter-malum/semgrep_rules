// test_xss_all.dart
// Универсальный тест для правил XSS:
// - xss-webview-js: Инъекция JavaScript в WebView
// - xss-webview-url: Инъекция через URL в WebView
// - xss-html-widget: Инъекция через Html виджет
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/material.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:flutter_html/flutter_html.dart';
import 'dart:convert';

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

String _sanitizeHtml(String input) {
  return input.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

bool _isValidUrl(String url) {
  try {
    Uri.parse(url);
    return true;
  } catch (_) {
    return false;
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: XSS через WebView JavaScript
// =============================================================================

void testRunJavaScript(String input) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript(input);
}

void testRunJavaScriptReturningResult(String input) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScriptReturningResult(input);
}

void testEvaluateJavascript(String input) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.evaluateJavascript(input);
}

void testRunJavaScriptWithVariable(String userScript) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript(userScript);
}

void testRunJavaScriptWithConcatenation(String userInput) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript('alert("' + userInput + '")');
}

void testRunJavaScriptWithInterpolation(String userInput) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript('console.log("$userInput")');
}

void testRunJavaScriptWithJson(Map<String, dynamic> userData) {
  final controller = WebViewController();
  String jsonData = jsonEncode(userData);
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript('processData($jsonData)');
}

void testRunJavaScriptInCallback() {
  final controller = WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)
    ..addJavaScriptChannel('Channel', onMessageReceived: (message) {
      // ruleid: flutter-xss-vulnerabilities
      controller.runJavaScript(message.message);
    });
}

void testRunJavaScriptFromUser(String userScript) {
  final controller = WebViewController();
  if (userScript.isNotEmpty) {
    // ruleid: flutter-xss-vulnerabilities
    controller.runJavaScript(userScript);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: XSS через WebView URL
// =============================================================================

void testLoadRequest(String url) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse(url));
}

void testLoadHtmlString(String html) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadHtmlString(html);
}

void testLoadFile(String path) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadFile(path);
}

void testLoadFlutterAsset(String key) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadFlutterAsset(key);
}

void testLoadWithUserUrl(String userUrl) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse(userUrl));
}

void testLoadWithDynamicUrl(String userPath, String userQuery) {
  final controller = WebViewController();
  String url = 'https://example.com/$userPath?q=$userQuery';
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse(url));
}

void testLoadWithUserParams(Map<String, String> userParams) {
  final controller = WebViewController();
  String query = userParams.entries.map((e) => '${e.key}=${e.value}').join('&');
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse('https://example.com?$query'));
}

void testLoadWithUserHtml(String userInput) {
  final controller = WebViewController();
  String html = '<html><body>$userInput</body></html>';
  // ruleid: flutter-xss-vulnerabilities
  controller.loadHtmlString(html);
}

void testLoadWithBaseUrl(String html, String baseUrl) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.loadHtmlString(html, baseUrl: Uri.parse(baseUrl));
}

void testLoadWithCondition(String url) {
  final controller = WebViewController();
  if (url.startsWith('https://')) {
    // ruleid: flutter-xss-vulnerabilities
    controller.loadRequest(Uri.parse(url));
  }
}

void testLoadWithUrlFromApi(String apiResponse) {
  final controller = WebViewController();
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse(data['url']));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: XSS через Html Widget
// =============================================================================

Widget testDirectHtml(String userHtml) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: userHtml);
}

Widget testHtmlWithVariable(String userContent) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: userContent);
}

Widget testHtmlWithInterpolation(String userMarkup) {
  String html = '<div>$userMarkup</div>';
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: html);
}

Widget testHtmlWithConcatenation(String userContent) {
  String html = '<div>' + userContent + '</div>';
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: html);
}

Widget testHtmlWithTemplate(String userHtml) {
  String template = '<div class="user">{content}</div>';
  String html = template.replaceAll('{content}', userHtml);
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: html);
}

Widget testHtmlWithJson(Map<String, String> userData) {
  String html = jsonEncode(userData);
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: html);
}

Widget testHtmlFromApi(String apiResponse) {
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: data['html']);
}

Widget testHtmlFromFile(String fileContent) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: fileContent);
}

Widget testHtmlFromDatabase(String dbResult) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: dbResult);
}

Widget testHtmlFromSharedPrefs(String prefs) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: prefs);
}

Widget testHtmlWithCondition(bool show, String html) {
  if (show) {
    // ruleid: flutter-xss-vulnerabilities
    return Html(data: html);
  }
  return Container();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Комбинированные XSS атаки
// =============================================================================

void testCombinedXSS(String userInput) {
  final controller = WebViewController();
  // ruleid: flutter-xss-vulnerabilities
  controller.runJavaScript(userInput);
  // ruleid: flutter-xss-vulnerabilities
  controller.loadRequest(Uri.parse('https://example.com?q=$userInput'));
  // ruleid: flutter-xss-vulnerabilities
  Html(data: userInput);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В StatefulWidget
// =============================================================================

class XSSStatefulWidget extends StatefulWidget {
  @override
  _XSSStatefulWidgetState createState() => _XSSStatefulWidgetState();
}

class _XSSStatefulWidgetState extends State<XSSStatefulWidget> {
  final WebViewController _controller = WebViewController();
  String _userInput = '';
  String _userHtml = '';

  @override
  void initState() {
    super.initState();
    // ruleid: flutter-xss-vulnerabilities
    _controller.runJavaScript('init()');
  }

  void _onTextChanged(String value) {
    // ruleid: flutter-xss-vulnerabilities
    _controller.runJavaScript('validate("$value")');
  }

  void _onUrlChanged(String url) {
    // ruleid: flutter-xss-vulnerabilities
    _controller.loadRequest(Uri.parse(url));
  }

  void _onHtmlChanged(String html) {
    setState(() {
      _userHtml = html;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          onChanged: _onTextChanged,
          onSubmitted: (value) {
            // ruleid: flutter-xss-vulnerabilities
            _controller.runJavaScript('submit("$value")');
            // ruleid: flutter-xss-vulnerabilities
            _controller.loadRequest(Uri.parse('https://example.com?input=$value'));
          },
        ),
        // ruleid: flutter-xss-vulnerabilities
        Html(data: _userHtml),
        // ruleid: flutter-xss-vulnerabilities
        WebViewWidget(controller: _controller),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В виджетах с контроллерами
// =============================================================================

class XSSWithControllers extends StatefulWidget {
  @override
  _XSSWithControllersState createState() => _XSSWithControllersState();
}

class _XSSWithControllersState extends State<XSSWithControllers> {
  late final WebViewController _controller;
  final TextEditingController _urlController = TextEditingController();
  final TextEditingController _jsController = TextEditingController();
  final TextEditingController _htmlController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel('UserChannel', onMessageReceived: (message) {
        // ruleid: flutter-xss-vulnerabilities
        _controller.runJavaScript(message.message);
      });
  }

  void _loadUrl() {
    // ruleid: flutter-xss-vulnerabilities
    _controller.loadRequest(Uri.parse(_urlController.text));
  }

  void _executeJs() {
    // ruleid: flutter-xss-vulnerabilities
    _controller.runJavaScript(_jsController.text);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: _urlController,
          onSubmitted: (_) => _loadUrl(),
        ),
        TextField(
          controller: _jsController,
          onSubmitted: (_) => _executeJs(),
        ),
        TextField(
          controller: _htmlController,
          onChanged: (value) {
            setState(() {});
          },
        ),
        // ruleid: flutter-xss-vulnerabilities
        Html(data: _htmlController.text),
        WebViewWidget(controller: _controller),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамическое создание
// =============================================================================

void createWebViewWithJs(String userData) {
  // ruleid: flutter-xss-vulnerabilities
  WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)
    ..runJavaScript(userData);
}

void createWebViewWithUrl(String userData) {
  // ruleid: flutter-xss-vulnerabilities
  WebViewController()
    ..loadRequest(Uri.parse(userData));
}

Widget createHtmlWidget(String userData) {
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: userData);
}

WebView createWebView(String userData) {
  // ruleid: flutter-xss-vulnerabilities
  return WebView(
    initialUrl: userData,
    javascriptMode: JavaScriptMode.unrestricted,
  );
}

WebView createWebViewWithJsChannel(String userData) {
  // ruleid: flutter-xss-vulnerabilities
  return WebView(
    initialUrl: 'https://example.com',
    javascriptMode: JavaScriptMode.unrestricted,
    onPageFinished: (url) {
      WebViewController().runJavaScript(userData);
    },
  );
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В циклах и списках
// =============================================================================

class XSSInLists extends StatelessWidget {
  final List<String> userInputs;
  final List<String> userUrls;
  final List<String> userHtmls;

  XSSInLists({
    required this.userInputs,
    required this.userUrls,
    required this.userHtmls,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        ...userInputs.map((input) => 
          WebView(
            initialUrl: 'https://example.com',
            onPageFinished: (_) => WebViewController().runJavaScript(input),
          )
        ),
        ...userUrls.map((url) => 
          WebView(
            initialUrl: url,
            javascriptMode: JavaScriptMode.unrestricted,
          )
        ),
        ...userHtmls.map((html) => Html(data: html)),
      ],
    );
  }

  void executeAllJs() {
    for (var input in userInputs) {
      // ruleid: flutter-xss-vulnerabilities
      WebViewController().runJavaScript(input);
    }
  }

  void loadAllUrls() {
    for (var url in userUrls) {
      // ruleid: flutter-xss-vulnerabilities
      WebViewController().loadRequest(Uri.parse(url));
    }
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование
// =============================================================================

void safeRunJavaScript(String userInput) {
  final controller = WebViewController();
  String safeJs = _sanitizeJs(userInput);
  // ok: flutter-xss-vulnerabilities
  controller.runJavaScript(safeJs);
}

void safeLoadUrl(String userInput) {
  final controller = WebViewController();
  if (_isValidUrl(userInput)) {
    // ok: flutter-xss-vulnerabilities
    controller.loadRequest(Uri.parse(userInput));
  }
}

Widget safeHtmlWidget(String userInput) {
  String safeHtml = _sanitizeHtml(userInput);
  // ok: flutter-xss-vulnerabilities
  return Html(data: safeHtml);
}

WebView safeWebView() {
  // ok: flutter-xss-vulnerabilities
  return WebView(
    initialUrl: 'https://example.com',
    javascriptMode: JavaScriptMode.disabled,
    onPageFinished: (url) {
      print('Page loaded: $url');
    },
  );
}

void safeJsWithWhitelist(String userInput) {
  final controller = WebViewController();
  if (_whitelist.contains(userInput)) {
    // ok: flutter-xss-vulnerabilities
    controller.runJavaScript(userInput);
  }
}

String _sanitizeJs(String input) {
  return input.replaceAll(RegExp(r''), '');
}

final List<String> _whitelist = ['console.log("safe")', 'alert("safe")'];

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Статические значения
// =============================================================================

void staticJs() {
  // ok: flutter-xss-vulnerabilities
  WebViewController().runJavaScript('console.log("static")');
}

void staticUrl() {
  // ok: flutter-xss-vulnerabilities
  WebViewController().loadRequest(Uri.parse('https://example.com'));
}

Widget staticHtml() {
  // ok: flutter-xss-vulnerabilities
  return Html(data: '<h1>Static HTML</h1>');
}

WebView staticWebView() {
  // ok: flutter-xss-vulnerabilities
  return const WebView(
    initialUrl: 'https://example.com',
    javascriptMode: JavaScriptMode.disabled,
  );
}

void staticJsFromConst() {
  const String script = 'console.log("const")';
  // ok: flutter-xss-vulnerabilities
  WebViewController().runJavaScript(script);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: С отключенным JavaScript
// =============================================================================

WebView webViewWithDisabledJs(String userInput) {
  // ok: flutter-xss-vulnerabilities
  return WebView(
    initialUrl: 'https://example.com',
    javascriptMode: JavaScriptMode.disabled,
    onPageFinished: (url) {
    },
  );
}

WebView webViewWithUrlOnly(String userInput) {
  // ok: flutter-xss-vulnerabilities
  return WebView(
    initialUrl: userInput,
    javascriptMode: JavaScriptMode.disabled,
  );
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: С валидацией URL
// =============================================================================

WebView validatedWebView(String userUrl) {
  if (_isSafeUrl(userUrl)) {
    // ok: flutter-xss-vulnerabilities
    return WebView(
      initialUrl: userUrl,
      javascriptMode: JavaScriptMode.unrestricted,
      navigationDelegate: (navigation) {
        if (_isSafeUrl(navigation.url)) {
          return NavigationDecision.navigate;
        }
        return NavigationDecision.prevent;
      },
    );
  }
  return WebView(initialUrl: 'about:blank');
}

bool _isSafeUrl(String url) {
  try {
    var uri = Uri.parse(url);
    return uri.hasScheme && 
           uri.scheme == 'https' &&
           !uri.toString().contains('<') &&
           !uri.toString().contains('>') &&
           !uri.toString().contains('javascript:');
  } catch (_) {
    return false;
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: С санитизацией HTML
// =============================================================================

Widget sanitizedHtmlWidget(String userHtml) {
  String clean = _cleanHtml(userHtml);
  // ok: flutter-xss-vulnerabilities
  return Html(data: clean);
}

String _cleanHtml(String html) {
  return html
      .replaceAll(RegExp(r'<script.*?>.*?</script>', dotAll: true), '')
      .replaceAll(RegExp(r'on\w+="[^"]*"'), '')
      .replaceAll('javascript:', '');
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Неполная санитизация
// =============================================================================

void partialJsSanitize(String userInput) {
  String unsafe = userInput.replaceAll('alert', '');
  // ruleid: flutter-xss-vulnerabilities
  WebViewController().runJavaScript(unsafe);
}

void partialUrlSanitize(String userInput) {
  String unsafe = userInput.replaceAll('javascript:', '');
  // ruleid: flutter-xss-vulnerabilities
  WebViewController().loadRequest(Uri.parse(unsafe));
}

Widget partialHtmlSanitize(String userInput) {
  String unsafe = userInput.replaceAll('<script>', '');
  // ruleid: flutter-xss-vulnerabilities
  return Html(data: unsafe);
}

void caseInsensitiveBypass(String userInput) {
  String unsafe = userInput.replaceAll(RegExp(r'SCRIPT', caseSensitive: false), '');
  // ruleid: flutter-xss-vulnerabilities
  WebViewController().runJavaScript(unsafe);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условное выполнение
// =============================================================================

void jsIfAdmin(String userInput, bool isAdmin) {
  if (isAdmin) {
    // ruleid: flutter-xss-vulnerabilities
    WebViewController().runJavaScript(userInput);
  }
}

void urlIfAdmin(String userInput, bool isAdmin) {
  if (isAdmin) {
    // ruleid: flutter-xss-vulnerabilities
    WebViewController().loadRequest(Uri.parse(userInput));
  }
}

Widget htmlIfAdmin(String userInput, bool isAdmin) {
  if (isAdmin) {
    // ruleid: flutter-xss-vulnerabilities
    return Html(data: userInput);
  }
  return Container();
}