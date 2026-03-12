// test_webview_vulnerabilities.dart
// Тест для правила: webview-vulnerabilities
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:io';
import 'dart:convert';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:flutter/material.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: webview-vulnerabilities
const String SAFE_WEB_URL = 'https://trusted.example.com';

// ok: webview-vulnerabilities
const String LOCAL_HTML = '<html><body>Safe content</body></html>';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Включение JavaScript
// =============================================================================

Future<Widget> testJavaScriptEnabled() async {
  // ruleid: webview-vulnerabilities
  final controller1 = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);

  // ruleid: webview-vulnerabilities
  final controller2 = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);

  // ruleid: webview-vulnerabilities
  return WebViewWidget(controller: WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted));
}

class WebViewConfig {
  // ruleid: webview-vulnerabilities
  static WebViewController configureInsecure() => WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: JavaScript интерфейсы с выполнением кода
// =============================================================================

Future<Widget> testJavaScriptInterface() async {
  // ruleid: webview-vulnerabilities
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel('Native', onMessageReceived: (msg) => eval(msg.message)),
  );
}

// ruleid: webview-vulnerabilities
final insecureController = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..addJavaScriptChannel('FileAccess', onMessageReceived: (msg) => File(msg.message).readAsString());

class BridgeInterface {
  // ruleid: webview-vulnerabilities
  void registerUnsafeBridge(WebViewController controller) {
    controller.addJavaScriptChannel('System', onMessageReceived: (msg) => Process.run(msg.message, []));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Доступ к файловой системе
// =============================================================================

Future<Widget> testFileAccess() async {
  // ruleid: webview-vulnerabilities
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..loadRequest(Uri.parse('file:///android_asset/index.html')),
  );
}

// ruleid: webview-vulnerabilities
final fileController = WebViewController()..loadRequest(Uri.parse('file:///sdcard/secret.txt'));

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Mixed Content и DOM Storage
// =============================================================================

Future<Widget> testMixedContent() async {
  // ruleid: webview-vulnerabilities
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setMixedContentMode(MixedContentMode.alwaysAllow),
  );
}

// ruleid: webview-vulnerabilities
final domStorageController = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..setDomStorageEnabled(true);

// ruleid: webview-vulnerabilities
final databaseController = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.unrestricted)
  ..setDatabaseEnabled(true);

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Unsafe URL loading
// =============================================================================

Future<void> testUnsafeUrlLoading(String userInput) async {
  // ruleid: webview-vulnerabilities
  await WebViewController().loadRequest(Uri.parse(userInput));
}

// ruleid: webview-vulnerabilities
Future<void> loadFromUntrustedSource(String url) async {
  await WebViewController().loadRequest(Uri.parse('http://$url'));
}

class UnsafeWebViewLoader {
  final _controller = WebViewController();
  
  // ruleid: webview-vulnerabilities
  Future<void> load(String endpoint) async => _controller.loadRequest(Uri.parse('http://api.example.com/$endpoint'));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: evaluateJavascript с непроверенным контентом
// =============================================================================

Future<void> testUnsafeEval(String jsCode) async {
  // ruleid: webview-vulnerabilities
  await WebViewController().runJavaScript(jsCode);
}

// ruleid: webview-vulnerabilities
Future<String> executeUserScript(String script) async {
  final result = await WebViewController().runJavaScriptReturningResult(script);
  return result.toString();
}

class ScriptExecutor {
  final controller = WebViewController();
  
  // ruleid: webview-vulnerabilities
  Future<void> inject(String code) async => controller.runJavaScript('eval("$code")');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: NavigationDelegate без валидации
// =============================================================================

// ruleid: webview-vulnerabilities
final permissiveDelegate = NavigationDelegate(onNavigationRequest: (req) => NavigationDecision.navigate);

// ruleid: webview-vulnerabilities
final noValidationDelegate = NavigationDelegate(onNavigationRequest: (req) => NavigationDecision.navigate);

class UnsafeNavigationDelegate extends NavigationDelegate {
  @override
  // ruleid: webview-vulnerabilities
  NavigationDecision onNavigationRequest(NavigationRequest request) => NavigationDecision.navigate;
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Комбинированные уязвимости
// =============================================================================

// ruleid: webview-vulnerabilities
Future<Widget> createFullyInsecureWebView() async {
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel('Bridge', onMessageReceived: (msg) => eval(msg.message))
      ..setMixedContentMode(MixedContentMode.alwaysAllow)
      ..loadRequest(Uri.parse('http://untrusted.example.com')),
  );
}

class DangerousWebViewFactory {
  // ruleid: webview-vulnerabilities
  static WebViewController create(String initialUrl) => WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)
    ..addJavaScriptChannel('NativeAPI', onMessageReceived: (msg) => Function(msg.message)())
    ..loadRequest(Uri.parse(initialUrl));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная конфигурация
// =============================================================================

Future<Widget> testSecureWebView() async {
  // ok: webview-vulnerabilities
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.disabled)
      ..loadRequest(Uri.parse('https://trusted.example.com')),
  );
}

// ok: webview-vulnerabilities
Future<Widget> createSecureWebViewWithJS() async {
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(
        NavigationDelegate(
          onNavigationRequest: (req) {
            // ok: webview-vulnerabilities
            if (Uri.parse(req.url).scheme != 'https') return NavigationDecision.prevent;
            // ok: webview-vulnerabilities
            if (!req.url.startsWith('https://trusted.example.com')) return NavigationDecision.prevent;
            return NavigationDecision.navigate;
          },
        ),
      ),
  );
}

// ok: webview-vulnerabilities
final secureController = WebViewController()
  ..setJavaScriptMode(JavaScriptMode.disabled)
  ..setDomStorageEnabled(false)
  ..setDatabaseEnabled(false);

// ok: webview-vulnerabilities
class SecureBridge {
  // ok: webview-vulnerabilities
  void registerSafeBridge(WebViewController controller) {
    controller.addJavaScriptChannel('SafeChannel', onMessageReceived: (msg) => print('Received: ${msg.message}'));
  }
}

// ok: webview-vulnerabilities
Future<void> loadTrustedContent() async => WebViewController().loadHtmlString(LOCAL_HTML);

// ok: webview-vulnerabilities
Future<void> loadAssetFile() async => WebViewController().loadRequest(Uri.parse('file:///android_asset/trusted.html'));

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Валидация и санитизация
// =============================================================================

// ok: webview-vulnerabilities
Future<void> loadWithValidation(String userInput) async {
  final uri = Uri.parse(userInput);
  // ok: webview-vulnerabilities
  if (uri.scheme != 'https') return;
  // ok: webview-vulnerabilities
  if (!['trusted.example.com', 'cdn.trusted.example.com'].contains(uri.host)) return;
  await WebViewController().loadRequest(uri);
}

// ok: webview-vulnerabilities
class ValidatedScriptRunner {
  final controller = WebViewController();
  
  // ok: webview-vulnerabilities
  Future<void> runSafeScript(String scriptName) async {
    const allowed = ['initApp', 'loadTheme', 'refreshUI'];
    // ok: webview-vulnerabilities
    if (!allowed.contains(scriptName)) return;
    await controller.runJavaScript('$scriptName()');
  }
}

// ok: webview-vulnerabilities
NavigationDecision safeNavigationCheck(NavigationRequest req) {
  // ok: webview-vulnerabilities
  final uri = Uri.parse(req.url);
  // ok: webview-vulnerabilities
  if (uri.scheme == 'file' || uri.scheme == 'content') return NavigationDecision.prevent;
  // ok: webview-vulnerabilities
  if (!uri.isScheme('https')) return NavigationDecision.prevent;
  return NavigationDecision.navigate;
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ
// =============================================================================

// ruleid: webview-vulnerabilities
Future<Widget> testPartialSecurity() async {
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..enableZoom(false),
  );
}

// ok: webview-vulnerabilities
Future<Widget> testDisabledJSWithFeatures() async {
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.disabled)
      ..setDomStorageEnabled(true)
      ..setDatabaseEnabled(true),
  );
}

// ruleid: webview-vulnerabilities
final conditionalJSController = WebViewController()..setJavaScriptMode(shouldEnableJS ? JavaScriptMode.unrestricted : JavaScriptMode.disabled);

// ok: webview-vulnerabilities (localhost для разработки)
@visibleForTesting
Future<Widget> createDebugWebView() async {
  return WebViewWidget(
    controller: WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..loadRequest(Uri.parse('http://localhost:8080/debug')),
  );
}

// ok: webview-vulnerabilities
Future<void> loadAboutBlank() async => WebViewController().loadRequest(Uri.parse('about:blank'));

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА
// =============================================================================

Future<void> testDetectionVariations() async {
  // ruleid: webview-vulnerabilities
  final v1 = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);

  // ruleid: webview-vulnerabilities
  final v2 = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);

  // ok: webview-vulnerabilities
  final safe1 = WebViewController()..setJavaScriptMode(JavaScriptMode.disabled);

  // ok: webview-vulnerabilities
  final safe2 = WebViewController()..setJavaScriptMode(JavaScriptMode.disabled);
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testStringNotCode() {
  // ok: webview-vulnerabilities
  final comment = 'Enable JavaScript with setJavaScriptMode(JavaScriptMode.unrestricted)';
  
  // ok: webview-vulnerabilities
  final config = {'javascriptEnabled': 'true'};
  
  // ok: webview-vulnerabilities
  print('Use JavaScriptMode.unrestricted for dynamic content');
}

// ruleid: webview-vulnerabilities
Future<void> testActualCodeUsage() async {
  // ruleid: webview-vulnerabilities
  await WebViewController().setJavaScriptMode(JavaScriptMode.unrestricted);
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

void _processPayment(String message) => print('Processing: $message');