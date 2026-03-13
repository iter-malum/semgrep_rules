// test_open_redirect.dart
// Тест для правил Open Redirect:
// - open-redirect-deeplink: Инъекция через Deep Links
// - open-redirect-oauth: Инъекция через OAuth редиректы
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';
import 'package:url_launcher/url_launcher.dart';
import 'dart:async';
import 'dart:convert';

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

bool _isValidUrl(String url) {
  try {
    final uri = Uri.parse(url);
    return uri.hasScheme && (uri.scheme == 'https' || uri.scheme == 'http');
  } catch (_) {
    return false;
  }
}

bool _isWhitelistedDomain(String url) {
  const whitelist = ['example.com', 'api.example.com'];
  try {
    final uri = Uri.parse(url);
    return whitelist.contains(uri.host);
  } catch (_) {
    return false;
  }
}

String _sanitizeRedirect(String url) {
  if (_isWhitelistedDomain(url)) {
    return url;
  }
  return 'https://example.com';
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Open Redirect через Deep Links
// =============================================================================

void testDeepLinkRedirect(String redirectUrl) async {
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(redirectUrl));
}

void testDeepLinkWithString(String redirectUrl) async {
  // ruleid: flutter-open-redirect
  await launch(redirectUrl);
}

void testDeepLinkInInit(String redirectUrl) {
  // ruleid: flutter-open-redirect
  launchUrl(Uri.parse(redirectUrl));
}

void testDeepLinkFromUserInput(String userInput) async {
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(userInput));
}

void testDeepLinkWithInterpolation(String baseUrl, String path) async {
  String url = '$baseUrl$path';
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(url));
}

void testDeepLinkWithConcatenation(String redirect) async {
  String url = 'https://' + redirect;
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(url));
}

void testDeepLinkFromApi(String apiResponse) async {
  var data = jsonDecode(apiResponse);
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(data['redirect_url']));
}

void testDeepLinkFromDatabase(String dbResult) async {
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(dbResult));
}

void testDeepLinkWithCondition(String url) async {
  if (url.isNotEmpty) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void testDeepLinkInCallback(String url) {
  Future.delayed(Duration(seconds: 1), () async {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  });
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Open Redirect через OAuth
// =============================================================================

class OAuthRedirect {
  final String redirectUri;
  final String state;
  
  OAuthRedirect({
    required this.redirectUri,
    required this.state,
  });

  void testOAuthRedirect(String redirectUrl) {
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(redirectUrl));
  }

  void testOAuthWithParams(String code, String state) {
    String url = '${redirectUri}?code=$code&state=$state';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testOAuthWithUserRedirect(String userRedirect) {
    String url = 'https://oauth.example.com/callback?redirect=$userRedirect&code=123';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testOAuthWithStateParam(String userState) {
    String url = '${redirectUri}?code=auth123&state=$userState';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testOAuthFromServer(String serverResponse) {
    var data = jsonDecode(serverResponse);
    String url = '${redirectUri}?code=${data['code']}&state=${data['state']}';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Deep Link обработчики
// =============================================================================

class DeepLinkHandler {
  void testHandleInitialLink() async {
    try {
      String? initialLink = await getInitialLink();
      if (initialLink != null) {
        // ruleid: flutter-open-redirect
        launchUrl(Uri.parse(initialLink));
      }
    } catch (e) {}
  }

  void testHandleLinkStream() {
    // ruleid: flutter-open-redirect
    getLinksStream().listen((String link) {
      launchUrl(Uri.parse(link));
    });
  }

  void testHandleLinkWithCondition() {
    getLinksStream().listen((String link) async {
      if (link.startsWith('https://')) {
        // ruleid: flutter-open-redirect
        await launchUrl(Uri.parse(link));
      }
    });
  }

  void testHandleDeepLinkInApp(String link) async {
    if (await canLaunchUrl(Uri.parse(link))) {
      // ruleid: flutter-open-redirect
      await launchUrl(Uri.parse(link));
    }
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: OAuth провайдеры
// =============================================================================

class OAuthProvider {
  final String clientId;
  final String redirectUri;

  OAuthProvider({
    required this.clientId,
    required this.redirectUri,
  });

  void testGoogleOAuth(String userRedirect) {
    String url = 'https://accounts.google.com/o/oauth2/v2/auth'
        '?client_id=$clientId'
        '&redirect_uri=$userRedirect'
        '&response_type=code';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testFacebookOAuth(String customRedirect) {
    String url = 'https://www.facebook.com/v12.0/dialog/oauth'
        '?client_id=$clientId'
        '&redirect_uri=$customRedirect';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testGithubOAuth(String state) {
    String url = 'https://github.com/login/oauth/authorize'
        '?client_id=$clientId'
        '&redirect_uri=$redirectUri'
        '&state=$state';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }

  void testOAuthWithDynamicRedirect(String baseUrl, String path) {
    String url = '$baseUrl/oauth/authorize?redirect_uri=$path';
    // ruleid: flutter-open-redirect
    launchUrl(Uri.parse(url));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: URL Launch вариации
// =============================================================================

void testLaunchMode(String url) async {
  // ruleid: flutter-open-redirect
  await launchUrl(
    Uri.parse(url),
    mode: LaunchMode.externalApplication,
  );
}

void testLaunchWithWebView(String url) async {
  // ruleid: flutter-open-redirect
  await launchUrl(
    Uri.parse(url),
    mode: LaunchMode.inAppWebView,
  );
}

void testLaunchWithUniversal(String url) async {
  // ruleid: flutter-open-redirect
  await launchUrl(
    Uri.parse(url),
    mode: LaunchMode.platformDefault,
  );
}

void testCanLaunchThenLaunch(String url) async {
  if (await canLaunchUrl(Uri.parse(url))) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void testLaunchWithForceWebView(String url) async {
  // ruleid: flutter-open-redirect
  await launchUrl(
    Uri.parse(url),
    mode: LaunchMode.inAppWebView,
    webViewConfiguration: const WebViewConfiguration(
      enableJavaScript: true,
      enableDomStorage: true,
    ),
  );
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В StatefulWidget
// =============================================================================

class OpenRedirectStatefulWidget extends StatefulWidget {
  @override
  _OpenRedirectStatefulWidgetState createState() => _OpenRedirectStatefulWidgetState();
}

class _OpenRedirectStatefulWidgetState extends State<OpenRedirectStatefulWidget> {
  String _redirectUrl = '';
  final TextEditingController _controller = TextEditingController();

  @override
  void initState() {
    super.initState();
    _setupDeepLinkListener();
  }

  void _setupDeepLinkListener() {
    // ruleid: flutter-open-redirect
    getLinksStream().listen((link) {
      _handleDeepLink(link);
    });
  }

  void _handleDeepLink(String link) async {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(link));
  }

  void _onRedirectChanged(String value) {
    setState(() {
      _redirectUrl = value;
    });
  }

  void _onSubmit() async {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(_redirectUrl));
  }

  void _onOAuthCallback(String code, String state) async {
    String url = 'https://app.example.com/callback?code=$code&state=$state';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: _controller,
          onChanged: _onRedirectChanged,
          onSubmitted: (_) => _onSubmit(),
        ),
        ElevatedButton(
          onPressed: () async {
            // ruleid: flutter-open-redirect
            await launchUrl(Uri.parse(_controller.text));
          },
          child: Text('Redirect'),
        ),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: OAuth в StatefulWidget
// =============================================================================

class OAuthStatefulWidget extends StatefulWidget {
  @override
  _OAuthStatefulWidgetState createState() => _OAuthStatefulWidgetState();
}

class _OAuthStatefulWidgetState extends State<OAuthStatefulWidget> {
  String _oauthRedirect = 'https://example.com/callback';
  String _clientId = 'client123';

  void _loginWithGoogle() async {
    String url = 'https://accounts.google.com/o/oauth2/v2/auth'
        '?client_id=$_clientId'
        '&redirect_uri=$_oauthRedirect'
        '&response_type=code';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void _loginWithFacebook(String customRedirect) async {
    String url = 'https://www.facebook.com/dialog/oauth'
        '?client_id=$_clientId'
        '&redirect_uri=$customRedirect';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void _handleOAuthResponse(Map<String, String> params) async {
    String code = params['code'] ?? '';
    String state = params['state'] ?? '';
    String url = '$_oauthRedirect?code=$code&state=$state';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          onChanged: (value) {
            setState(() {
              _oauthRedirect = value;
            });
          },
        ),
        ElevatedButton(
          onPressed: _loginWithGoogle,
          child: Text('Login with Google'),
        ),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамические редиректы
// =============================================================================

class DynamicRedirects {
  void testRedirectWithParams(Map<String, String> params) async {
    String url = 'https://auth.example.com/login'
        '?redirect=${params['redirect']}'
        '&state=${params['state']}';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void testRedirectWithEncoding(String redirect) async {
    String encoded = Uri.encodeComponent(redirect);
    String url = 'https://auth.example.com/callback?redirect=$encoded';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void testRedirectFromJson(String jsonString) async {
    var data = jsonDecode(jsonString);
    String url = 'https://api.example.com/oauth?redirect=${data['return_url']}';
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void testRedirectWithBase(String base, String path) async {
    String url = base + path;
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В циклах и списках
// =============================================================================

class RedirectInLists extends StatelessWidget {
  final List<String> redirectUrls;

  RedirectInLists({required this.redirectUrls});

  void processAllRedirects() async {
    for (var url in redirectUrls) {
      // ruleid: flutter-open-redirect
      await launchUrl(Uri.parse(url));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: redirectUrls.map((url) {
        return ElevatedButton(
          onPressed: () async {
            // ruleid: flutter-open-redirect
            await launchUrl(Uri.parse(url));
          },
          child: Text('Redirect to $url'),
        );
      }).toList(),
    );
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные редиректы
// =============================================================================

void safeRedirectWithValidation(String url) async {
  if (_isWhitelistedDomain(url)) {
    // ok: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void safeRedirectWithWhitelist(String url) async {
  const whitelist = ['example.com', 'api.example.com'];
  try {
    final uri = Uri.parse(url);
    if (whitelist.contains(uri.host)) {
      // ok: flutter-open-redirect
      await launchUrl(uri);
    }
  } catch (_) {}
}

void safeRedirectWithSchemeCheck(String url) async {
  try {
    final uri = Uri.parse(url);
    if (uri.scheme == 'https' && uri.host == 'example.com') {
      // ok: flutter-open-redirect
      await launchUrl(uri);
    }
  } catch (_) {}
}

void safeRedirectWithSanitization(String url) async {
  String safeUrl = _sanitizeRedirect(url);
  // ok: flutter-open-redirect
  await launchUrl(Uri.parse(safeUrl));
}

void safeOAuthRedirect(String redirectUri) async {
  if (redirectUri.startsWith('https://example.com/')) {
    // ok: flutter-open-redirect
    await launchUrl(Uri.parse(redirectUri));
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Статические редиректы
// =============================================================================

void staticRedirect() async {
  // ok: flutter-open-redirect
  await launchUrl(Uri.parse('https://example.com/home'));
}

void staticOAuthRedirect() async {
  String url = 'https://accounts.google.com/o/oauth2/v2/auth'
      '?client_id=123'
      '&redirect_uri=https://example.com/callback'
      '&response_type=code';
  // ok: flutter-open-redirect
  await launchUrl(Uri.parse(url));
}

void staticDeepLink() async {
  const String link = 'https://example.com/deep-link';
  // ok: flutter-open-redirect
  await launchUrl(Uri.parse(link));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Редиректы с проверкой canLaunch
// =============================================================================

void safeRedirectWithCanLaunch(String url) async {
  final uri = Uri.parse(url);
  if (await canLaunchUrl(uri) && _isWhitelistedDomain(url)) {
    // ok: flutter-open-redirect
    await launchUrl(uri);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: OAuth с фиксированным redirect_uri
// =============================================================================

class SafeOAuthProvider {
  final String clientId = 'client123';
  final String redirectUri = 'https://example.com/oauth/callback';

  void loginWithGoogle() async {
    String url = 'https://accounts.google.com/o/oauth2/v2/auth'
        '?client_id=$clientId'
        '&redirect_uri=$redirectUri'
        '&response_type=code';
    // ok: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }

  void loginWithFacebook() async {
    String url = 'https://www.facebook.com/dialog/oauth'
        '?client_id=$clientId'
        '&redirect_uri=$redirectUri';
    // ok: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Deep Link с валидацией
// =============================================================================

class SafeDeepLinkHandler {
  final List<String> allowedDomains = ['example.com', 'app.example.com'];

  void handleLink(String link) async {
    try {
      final uri = Uri.parse(link);
      if (allowedDomains.contains(uri.host)) {
        // ok: flutter-open-redirect
        await launchUrl(uri);
      }
    } catch (_) {}
  }

  void handleLinkStream() {
    // ok: flutter-open-redirect
    getLinksStream().listen((link) {
      try {
        final uri = Uri.parse(link);
        if (allowedDomains.contains(uri.host)) {
          launchUrl(uri);
        }
      } catch (_) {}
    });
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Неполная валидация
// =============================================================================

void partialValidationRedirect(String url) async {
  if (url.startsWith('https://')) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void partialDomainCheck(String url) async {
  if (url.contains('example.com')) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void partialSchemeCheck(String url) async {
  if (url.startsWith('https')) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void partialOAuthCheck(String redirect) async {
  if (redirect.length < 100) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(redirect));
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условные редиректы
// =============================================================================

void conditionalRedirect(String url, bool isAuthenticated) async {
  if (isAuthenticated) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

void adminRedirect(String url, bool isAdmin) async {
  if (isAdmin) {
    // ruleid: flutter-open-redirect
    await launchUrl(Uri.parse(url));
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Редиректы с экранированием
// =============================================================================

void redirectWithEscaping(String input) async {
  String url = Uri.encodeFull(input);
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(url));
}

void redirectWithDecoding(String input) async {
  String url = Uri.decodeFull(input);
  // ruleid: flutter-open-redirect
  await launchUrl(Uri.parse(url));
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ПЕРЕМЕННЫЕ
// =============================================================================

String userRedirect = 'https://malicious.com';
String oauthState = 'state123';
String authCode = 'auth123';
String deepLink = 'myapp://redirect?url=https://evil.com';
String apiResponse = '{"redirect_url": "https://malicious.com"}';