// test_html_injection.dart
// Тест для правила: html-injection-flutter_html
// Правило ищет рендеринг непроверенного HTML через пакет flutter_html
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/material.dart';
import 'package:flutter_html/flutter_html.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'dart:convert';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямая вставка пользовательского HTML
// =============================================================================

class TestWidgets extends StatelessWidget {
  final String userInput;
  final String userComment;
  final String message;
  final String htmlContent;
  final String richText;

  // ruleid: html-injection-flutter_html
  Widget testDirectHtml1() {
    return Html(data: userInput);
  }

  // ruleid: html-injection-flutter_html
  Widget testDirectHtml2() {
    return Html(data: userComment);
  }

  // ruleid: html-injection-flutter_html
  Widget testDirectHtml3() {
    return Html(data: message);
  }

  // ruleid: html-injection-flutter_html
  Widget testDirectHtml4() {
    return Html(data: htmlContent);
  }

  // ruleid: html-injection-flutter_html
  Widget testDirectHtml5() {
    return Html(data: richText);
  }

  @override
  Widget build(BuildContext context) {
    // ruleid: html-injection-flutter_html
    return Html(data: userInput);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамическое формирование HTML
// =============================================================================

class DynamicHtmlWidget extends StatelessWidget {
  final String username;
  final String userBio;
  final String postContent;
  final String comment;
  final String profileData;

  // ruleid: html-injection-flutter_html
  Widget buildUserProfile() {
    String html = '<div><h1>$username</h1><p>$userBio</p></div>';
    return Html(data: html);
  }

  // ruleid: html-injection-flutter_html
  Widget buildPost() {
    String html = '<article>$postContent</article>';
    return Html(data: html);
  }

  // ruleid: html-injection-flutter_html
  Widget buildComment() {
    String html = '<div class="comment">$comment</div>';
    return Html(data: html);
  }

  // ruleid: html-injection-flutter_html
  Widget buildProfile() {
    String html = '<div>${profileData.replaceAll('<', '&lt;')}</div>';
    return Html(data: html);
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithTemplate() {
    String template = '<div class="user">{user}</div>';
    String html = template.replaceAll('{user}', username);
    return Html(data: html);
  }

  @override
  Widget build(BuildContext context) {
    // ruleid: html-injection-flutter_html
    String html = '<span>$username</span>';
    return Html(data: html);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML из внешних источников
// =============================================================================

class ExternalHtmlWidget extends StatefulWidget {
  @override
  _ExternalHtmlWidgetState createState() => _ExternalHtmlWidgetState();
}

class _ExternalHtmlWidgetState extends State<ExternalHtmlWidget> {
  String apiResponse = '';
  String localStorage = '';
  String fileContent = '';
  String databaseData = '';
  String sharedPrefs = '';

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    // Имитация загрузки данных
    apiResponse = await fetchFromApi();
    localStorage = await readFromStorage();
    fileContent = await readFile();
    databaseData = await queryDatabase();
    sharedPrefs = await getSharedPrefs();
    setState(() {});
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromApi() {
    return Html(data: apiResponse);
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromStorage() {
    return Html(data: localStorage);
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromFile() {
    return Html(data: fileContent);
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromDatabase() {
    return Html(data: databaseData);
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromPrefs() {
    return Html(data: sharedPrefs);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // ruleid: html-injection-flutter_html
        Html(data: apiResponse),
        // ruleid: html-injection-flutter_html
        Html(data: localStorage),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML в списках и циклах
// =============================================================================

class ListHtmlWidget extends StatelessWidget {
  final List<String> comments;
  final List<Map<String, String>> posts;
  final List<String> messages;

  // ruleid: html-injection-flutter_html
  Widget buildComments() {
    return Column(
      children: comments.map((comment) => Html(data: comment)).toList(),
    );
  }

  // ruleid: html-injection-flutter_html
  Widget buildPosts() {
    return ListView.builder(
      itemCount: posts.length,
      itemBuilder: (context, index) {
        // ruleid: html-injection-flutter_html
        return Html(data: posts[index]['content']!);
      },
    );
  }

  // ruleid: html-injection-flutter_html
  Widget buildMessages() {
    return ListView(
      children: [
        for (var msg in messages)
          // ruleid: html-injection-flutter_html
          Html(data: msg),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // ruleid: html-injection-flutter_html
        ...comments.map((c) => Html(data: c)),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML из параметров и аргументов
// =============================================================================

class ParamHtmlWidget extends StatelessWidget {
  final String content;

  ParamHtmlWidget({required this.content});

  // ruleid: html-injection-flutter_html
  Widget buildWithParam() {
    return Html(data: content);
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithNamedParam({required String html}) {
    return Html(data: html);
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithOptionalParam([String? html = '']) {
    return Html(data: html ?? '');
  }

  @override
  Widget build(BuildContext context) {
    // ruleid: html-injection-flutter_html
    return Html(data: content);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Условный рендеринг HTML
// =============================================================================

class ConditionalHtmlWidget extends StatelessWidget {
  final String userHtml;
  final bool isAdmin;
  final int userRole;

  // ruleid: html-injection-flutter_html
  Widget buildConditional() {
    if (isAdmin) {
      return Html(data: userHtml);
    }
    return Text('Access denied');
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithSwitch() {
    switch (userRole) {
      case 1:
        return Html(data: userHtml);
      default:
        return Text('No access');
    }
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithTernary() {
    return isAdmin ? Html(data: userHtml) : Text('No access');
  }

  @override
  Widget build(BuildContext context) {
    // ruleid: html-injection-flutter_html
    return isAdmin ? Html(data: userHtml) : Container();
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML в StatefulWidget с обновлением
// =============================================================================

class DynamicUpdateWidget extends StatefulWidget {
  @override
  _DynamicUpdateWidgetState createState() => _DynamicUpdateWidgetState();
}

class _DynamicUpdateWidgetState extends State<DynamicUpdateWidget> {
  String _dynamicHtml = '';

  void updateFromUser(String input) {
    setState(() {
      // ruleid: html-injection-flutter_html
      _dynamicHtml = input;
    });
  }

  void updateFromApi(String apiData) {
    setState(() {
      // ruleid: html-injection-flutter_html
      _dynamicHtml = apiData;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // ruleid: html-injection-flutter_html
        Html(data: _dynamicHtml),
        TextField(
          onChanged: (value) {
            setState(() {
              // ruleid: html-injection-flutter_html
              _dynamicHtml = value;
            });
          },
        ),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML через Stream и FutureBuilder
// =============================================================================

class StreamHtmlWidget extends StatelessWidget {
  final Stream<String> htmlStream;
  final Future<String> htmlFuture;

  // ruleid: html-injection-flutter_html
  Widget buildWithStream() {
    return StreamBuilder<String>(
      stream: htmlStream,
      builder: (context, snapshot) {
        if (snapshot.hasData) {
          return Html(data: snapshot.data!);
        }
        return CircularProgressIndicator();
      },
    );
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithFuture() {
    return FutureBuilder<String>(
      future: htmlFuture,
      builder: (context, snapshot) {
        if (snapshot.hasData) {
          return Html(data: snapshot.data!);
        }
        return CircularProgressIndicator();
      },
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML из контроллеров и форм
// =============================================================================

class FormHtmlWidget extends StatefulWidget {
  @override
  _FormHtmlWidgetState createState() => _FormHtmlWidgetState();
}

class _FormHtmlWidgetState extends State<FormHtmlWidget> {
  final TextEditingController _controller = TextEditingController();
  String _submittedHtml = '';

  // ruleid: html-injection-flutter_html
  void _handleSubmit(String value) {
    setState(() {
      _submittedHtml = value;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: _controller,
          onSubmitted: _handleSubmit,
        ),
        // ruleid: html-injection-flutter_html
        Html(data: _submittedHtml),
        // ruleid: html-injection-flutter_html
        Html(data: _controller.text),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML в кастомных виджетах
// =============================================================================

class CustomHtmlRenderer extends StatelessWidget {
  final String source;

  // ruleid: html-injection-flutter_html
  const CustomHtmlRenderer(this.source);

  @override
  Widget build(BuildContext context) {
    return Container(
      child: Html(data: source),
    );
  }
}

// ruleid: html-injection-flutter_html
class HtmlWidgetWrapper extends StatelessWidget {
  final String content;
  HtmlWidgetWrapper(this.content);

  @override
  Widget build(BuildContext context) {
    return Html(data: content);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML с преобразованиями
// =============================================================================

class TransformedHtmlWidget extends StatelessWidget {
  final String rawInput;

  // ruleid: html-injection-flutter_html
  Widget buildWithTrim() {
    return Html(data: rawInput.trim());
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithToLowerCase() {
    return Html(data: rawInput.toLowerCase());
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithSubstring() {
    return Html(data: rawInput.substring(0, 100));
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithReplace() {
    return Html(data: rawInput.replaceAll('<script>', ''));
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithJoin() {
    return Html(data: [rawInput, '<br/>', rawInput].join(''));
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: HTML в различных контекстах
// =============================================================================

class VariousContextsWidget extends StatelessWidget {
  final String userHtml;

  // ruleid: html-injection-flutter_html
  Widget inColumn() {
    return Column(
      children: [
        Text('Title'),
        Html(data: userHtml),
        Text('Footer'),
      ],
    );
  }

  // ruleid: html-injection-flutter_html
  Widget inRow() {
    return Row(
      children: [
        Icon(Icons.info),
        Expanded(child: Html(data: userHtml)),
      ],
    );
  }

  // ruleid: html-injection-flutter_html
  Widget inContainer() {
    return Container(
      padding: EdgeInsets.all(8),
      child: Html(data: userHtml),
    );
  }

  // ruleid: html-injection-flutter_html
  Widget inCard() {
    return Card(
      child: Html(data: userHtml),
    );
  }

  // ruleid: html-injection-flutter_html
  Widget inExpansionTile() {
    return ExpansionTile(
      title: Text('Details'),
      children: [Html(data: userHtml)],
    );
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование с очисткой HTML
// =============================================================================

class SafeHtmlWidget extends StatelessWidget {
  final String userInput;

  // ok: html-injection-flutter_html
  Widget buildWithSanitizer() {
    String sanitized = sanitizeHtml(userInput);
    return Html(data: sanitized);
  }

  // ok: html-injection-flutter_html
  Widget buildWithBleach() {
    String clean = bleachHtml(userInput);
    return Html(data: clean);
  }

  // ok: html-injection-flutter_html
  Widget buildWithCustomSanitizer() {
    String safe = _customSanitize(userInput);
    return Html(data: safe);
  }

  String _customSanitize(String input) {
    return input.replaceAll(RegExp(r'<[^>]*>'), '');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Статический HTML без переменных
// =============================================================================

class StaticHtmlWidget extends StatelessWidget {
  // ok: html-injection-flutter_html
  Widget buildStatic1() {
    return Html(data: '<h1>Hello World</h1>');
  }

  // ok: html-injection-flutter_html
  Widget buildStatic2() {
    return Html(data: '<div class="content">Static content</div>');
  }

  // ok: html-injection-flutter_html
  Widget buildStatic3() {
    const String staticHtml = '<p>This is safe static HTML</p>';
    return Html(data: staticHtml);
  }

  // ok: html-injection-flutter_html
  Widget buildFromConst() {
    const String html = '<b>Bold text</b>';
    return Html(data: html);
  }

  @override
  Widget build(BuildContext context) {
    // ok: html-injection-flutter_html
    return Html(data: '<h1>Welcome</h1>');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование параметризованных данных
// =============================================================================

class ParametrizedHtmlWidget extends StatelessWidget {
  final String userName;
  final String userBio;

  // ok: html-injection-flutter_html
  Widget buildSafeWithHtmlEscape() {
    String safeName = htmlEscape.convert(userName);
    String safeBio = htmlEscape.convert(userBio);
    String html = '<h1>$safeName</h1><p>$safeBio</p>';
    return Html(data: html);
  }

  // ok: html-injection-flutter_html
  Widget buildSafeWithEncoder() {
    String encoded = const HtmlEscape().convert(userName);
    return Html(data: '<div>$encoded</div>');
  }

  // ok: html-injection-flutter_html
  Widget buildSafeWithTemplate() {
    String safe = _encodeHtml(userName);
    return Html(data: '<span>$safe</span>');
  }

  String _encodeHtml(String input) {
    return input
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование других пакетов/виджетов
// =============================================================================

class OtherWidgetsTest extends StatelessWidget {
  final String text;

  // ok: html-injection-flutter_html
  Widget buildWithText() {
    return Text(text);
  }

  // ok: html-injection-flutter_html
  Widget buildWithRichText() {
    return RichText(
      text: TextSpan(text: text),
    );
  }

  // ok: html-injection-flutter_html
  Widget buildWithSelectableText() {
    return SelectableText(text);
  }

  // ok: html-injection-flutter_html
  Widget buildWithWebView() {
    return WebView(
      initialUrl: 'https://example.com',
    );
  }

  // ok: html-injection-flutter_html
  Widget buildWithWebViewHtml() {
    return WebView(
      initialUrl: 'about:blank',
      onPageFinished: (_) {},
    );
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Данные из белого списка
// =============================================================================

class WhitelistHtmlWidget extends StatelessWidget {
  final String htmlType;
  final Map<String, String> predefinedHtml = {
    'welcome': '<h1>Welcome!</h1>',
    'about': '<p>About us page</p>',
    'contact': '<div>Contact info</div>',
  };

  // ok: html-injection-flutter_html
  Widget buildFromWhitelist() {
    String html = predefinedHtml[htmlType] ?? '<p>Default</p>';
    return Html(data: html);
  }

  // ok: html-injection-flutter_html
  Widget buildWithEnum(HtmlPage page) {
    switch (page) {
      case HtmlPage.welcome:
        return Html(data: '<h1>Welcome</h1>');
      case HtmlPage.terms:
        return Html(data: '<div>Terms of service</div>');
    }
  }
}

enum HtmlPage { welcome, terms }

// =============================================================================
// НЕГРАНИЧНЫЕ ТЕСТЫ: Комментарии и строки, не являющиеся кодом
// =============================================================================

void testNonCode() {
  // ok: html-injection-flutter_html
  String comment = 'Html(data: userInput)'; // просто строка

  // ok: html-injection-flutter_html
  String doc = '''
    Example of unsafe usage:
    Html(data: userProvidedHtml)
  ''';

  // ok: html-injection-flutter_html
  Map config = {
    'widget': 'Html',
    'data': 'userInput'
  };
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная очистка (недостаточная)
// =============================================================================

// ruleid: html-injection-flutter_html
class InsufficientSanitizationWidget extends StatelessWidget {
  final String userHtml;

  // ruleid: html-injection-flutter_html
  Widget buildWithPartialSanitize() {
    String partiallySanitized = userHtml.replaceAll('<script>', '');
    return Html(data: partiallySanitized); // <script> может быть в разных регистрах
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithRemoveScript() {
    String withoutScript = userHtml.replaceAll(RegExp(r'<script.*?>.*?</script>', dotAll: true), '');
    return Html(data: withoutScript); // всё ещё опасны onclick и другие атрибуты
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithRemoveTags() {
    String withoutTags = userHtml.replaceAll(RegExp(r'<[^>]*>'), '');
    return Html(data: withoutTags); // потеря форматирования, но может быть безопасно
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Динамические имена виджетов
// =============================================================================

class DynamicWidgetName extends StatelessWidget {
  final String htmlContent;

  // ruleid: html-injection-flutter_html
  Widget buildWithDynamic() {
    var widget = Html;
    return widget(data: htmlContent);
  }

  // ruleid: html-injection-flutter_html
  Widget buildWithMap() {
    Map<String, dynamic> widgets = {
      'html': Html(data: htmlContent),
    };
    return widgets['html'];
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: HTML в различных типах данных
// =============================================================================

class VariousDataTypesWidget extends StatelessWidget {
  final dynamic userData;

  // ruleid: html-injection-flutter_html
  Widget buildFromDynamic() {
    if (userData is String) {
      return Html(data: userData);
    }
    return Container();
  }

  // ruleid: html-injection-flutter_html
  Widget buildFromObject() {
    if (userData is Map && userData.containsKey('html')) {
      return Html(data: userData['html'] as String);
    }
    return Container();
  }
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

// Санитайзеры (для негативных тестов)
String sanitizeHtml(String input) {
  // Простой санитайзер (в реальности использовать html_escape или bleach)
  return input.replaceAll(RegExp(r'<[^>]*>'), '');
}

String bleachHtml(String input) {
  // Имитация bleach
  return input.replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

// Функции для имитации загрузки данных
Future<String> fetchFromApi() async => '<div>API Response</div>';
Future<String> readFromStorage() async => '<span>Storage data</span>';
Future<String> readFile() async => '<p>File content</p>';
Future<String> queryDatabase() async => '<b>DB result</b>';
Future<String> getSharedPrefs() async => '<i>Prefs value</i>';