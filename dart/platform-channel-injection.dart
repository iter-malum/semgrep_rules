// test_platform_channel_injection.dart
// Тест для правила: platform-channel-injection
// Правило ищет передачу непроверенных пользовательских данных в MethodChannel
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:flutter/services.dart';
import 'dart:convert';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямая передача пользовательского ввода
// =============================================================================

class DirectChannelInjection {
  static const platform = MethodChannel('com.example/app');

  final String userInput;
  final String userCommand;
  final String userData;
  final Map<String, dynamic> userMap;
  final List<String> userList;

  DirectChannelInjection({
    required this.userInput,
    required this.userCommand,
    required this.userData,
    required this.userMap,
    required this.userList,
  });

  // ruleid: platform-channel-injection
  void testDirectString() {
    platform.invokeMethod('process', userInput);
  }

  // ruleid: platform-channel-injection
  void testDirectCommand() {
    platform.invokeMethod(userCommand);
  }

  // ruleid: platform-channel-injection
  void testDirectWithArgs() {
    platform.invokeMethod('process', {'data': userData});
  }

  // ruleid: platform-channel-injection
  void testDirectMap() {
    platform.invokeMethod('process', userMap);
  }

  // ruleid: platform-channel-injection
  void testDirectList() {
    platform.invokeMethod('process', userList);
  }

  // ruleid: platform-channel-injection
  Future<void> testDirectAsync() async {
    await platform.invokeMethod('execute', userInput);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Данные из контроллеров и форм
// =============================================================================

class FormChannelInjection extends StatefulWidget {
  @override
  _FormChannelInjectionState createState() => _FormChannelInjectionState();
}

class _FormChannelInjectionState extends State<FormChannelInjection> {
  static const platform = MethodChannel('com.example/app');
  final TextEditingController _controller = TextEditingController();
  String _textFieldValue = '';

  // ruleid: platform-channel-injection
  void _submitFromController() {
    platform.invokeMethod('submit', _controller.text);
  }

  // ruleid: platform-channel-injection
  void _submitFromState() {
    platform.invokeMethod('submit', _textFieldValue);
  }

  // ruleid: platform-channel-injection
  void _submitOnChanged(String value) {
    platform.invokeMethod('validate', value);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        TextField(
          controller: _controller,
          onChanged: (value) {
            // ruleid: platform-channel-injection
            platform.invokeMethod('preview', value);
            setState(() {
              _textFieldValue = value;
            });
          },
          onSubmitted: (value) {
            // ruleid: platform-channel-injection
            platform.invokeMethod('process', value);
          },
        ),
      ],
    );
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Данные из внешних источников
// =============================================================================

class ExternalSourceInjection {
  static const platform = MethodChannel('com.example/app');

  // ruleid: platform-channel-injection
  Future<void> fromApi() async {
    final response = await fetchFromApi();
    await platform.invokeMethod('api_data', response);
  }

  // ruleid: platform-channel-injection
  Future<void> fromDatabase() async {
    final data = await queryDatabase();
    platform.invokeMethod('db_result', data);
  }

  // ruleid: platform-channel-injection
  Future<void> fromFile() async {
    final content = await readFile();
    platform.invokeMethod('file_content', content);
  }

  // ruleid: platform-channel-injection
  Future<void> fromSharedPrefs() async {
    final prefs = await getSharedPrefs();
    platform.invokeMethod('preferences', prefs);
  }

  // ruleid: platform-channel-injection
  void fromClipboard() async {
    final clipboard = await Clipboard.getData('text/plain');
    platform.invokeMethod('clipboard_data', clipboard?.text);
  }

  // ruleid: platform-channel-injection
  void fromQRCode(String qrData) {
    platform.invokeMethod('qr_scanned', qrData);
  }

  // ruleid: platform-channel-injection
  void fromDeepLink(String link) {
    platform.invokeMethod('deeplink', link);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамическое формирование данных
// =============================================================================

class DynamicDataInjection {
  static const platform = MethodChannel('com.example/app');
  
  final String userName;
  final String userEmail;
  final String userPhone;

  DynamicDataInjection({
    required this.userName,
    required this.userEmail,
    required this.userPhone,
  });

  // ruleid: platform-channel-injection
  void buildAndSend() {
    Map<String, dynamic> userData = {
      'name': userName,
      'email': userEmail,
      'phone': userPhone,
    };
    platform.invokeMethod('register', userData);
  }

  // ruleid: platform-channel-injection
  void buildWithTemplate() {
    String command = 'user_${userName}_action';
    platform.invokeMethod(command);
  }

  // ruleid: platform-channel-injection
  void buildWithConcatenation() {
    String data = 'Name: ' + userName + ', Email: ' + userEmail;
    platform.invokeMethod('log', data);
  }

  // ruleid: platform-channel-injection
  void buildWithInterpolation() {
    platform.invokeMethod('greet', 'Hello, $userName!');
  }

  // ruleid: platform-channel-injection
  void buildWithJsonEncode() {
    String json = jsonEncode({'user': userName, 'action': 'login'});
    platform.invokeMethod('json_data', json);
  }

  // ruleid: platform-channel-injection
  void buildWithList() {
    List<dynamic> items = [userName, userEmail, userPhone];
    platform.invokeMethod('batch_process', items);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Условная отправка
// =============================================================================

class ConditionalInjection {
  static const platform = MethodChannel('com.example/app');
  
  final String userInput;
  final bool isValid;
  final int userRole;

  ConditionalInjection({
    required this.userInput,
    required this.isValid,
    required this.userRole,
  });

  // ruleid: platform-channel-injection
  void sendIfValid() {
    if (isValid) {
      platform.invokeMethod('process', userInput);
    }
  }

  // ruleid: platform-channel-injection
  void sendWithSwitch() {
    switch (userRole) {
      case 1:
        platform.invokeMethod('admin_action', userInput);
        break;
      case 2:
        platform.invokeMethod('user_action', userInput);
        break;
      default:
        break;
    }
  }

  // ruleid: platform-channel-injection
  void sendWithTernary() {
    platform.invokeMethod(isValid ? 'valid' : 'invalid', userInput);
  }

  // ruleid: platform-channel-injection
  void sendWithNullCheck() {
    if (userInput.isNotEmpty) {
      platform.invokeMethod('not_null', userInput);
    }
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В колбэках и обработчиках
// =============================================================================

class CallbackInjection {
  static const platform = MethodChannel('com.example/app');

  // ruleid: platform-channel-injection
  void onButtonPressed(String data) {
    platform.invokeMethod('button_click', data);
  }

  // ruleid: platform-channel-injection
  void onTextChanged(String text) {
    platform.invokeMethod('text_update', text);
  }

  // ruleid: platform-channel-injection
  void onDropdownChanged(String? value) {
    if (value != null) {
      platform.invokeMethod('dropdown_select', value);
    }
  }

  // ruleid: platform-channel-injection
  void onDatePicked(DateTime date) {
    platform.invokeMethod('date_selected', date.toIso8601String());
  }

  // ruleid: platform-channel-injection
  void onFilePicked(String path) {
    platform.invokeMethod('file_selected', path);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В Stream и FutureBuilder
// =============================================================================

class StreamChannelInjection {
  static const platform = MethodChannel('com.example/app');
  
  final Stream<String> userInputStream;
  final Future<String> userInputFuture;

  StreamChannelInjection({
    required this.userInputStream,
    required this.userInputFuture,
  });

  // ruleid: platform-channel-injection
  void subscribeToStream() {
    userInputStream.listen((data) {
      platform.invokeMethod('stream_data', data);
    });
  }

  // ruleid: platform-channel-injection
  Future<void> processFuture() async {
    final data = await userInputFuture;
    await platform.invokeMethod('future_data', data);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Различные типы MethodChannel
// =============================================================================

class VariousChannelTypes {
  final String userInput;

  VariousChannelTypes(this.userInput);

  // ruleid: platform-channel-injection
  void basicChannel() {
    const channel = MethodChannel('com.example/basic');
    channel.invokeMethod('test', userInput);
  }

  // ruleid: platform-channel-injection
  void optionalMethodChannel() {
    const channel = OptionalMethodChannel('com.example/optional');
    channel.invokeMethod('test', userInput);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Вложенные и сложные структуры
// =============================================================================

class ComplexDataInjection {
  static const platform = MethodChannel('com.example/app');

  final Map<String, dynamic> nestedUserData;

  ComplexDataInjection(this.nestedUserData);

  // ruleid: platform-channel-injection
  void sendNestedMap() {
    platform.invokeMethod('complex', {
      'user': nestedUserData,
      'metadata': {
        'timestamp': DateTime.now().toIso8601String(),
        'source': 'mobile',
      },
    });
  }

  // ruleid: platform-channel-injection
  void sendListOfMaps() {
    List<Map<String, dynamic>> items = [
      {'id': '1', 'data': nestedUserData['field1']},
      {'id': '2', 'data': nestedUserData['field2']},
    ];
    platform.invokeMethod('batch', items);
  }

  // ruleid: platform-channel-injection
  void sendWithEncoding() {
    String encoded = base64Encode(utf8.encode(nestedUserData.toString()));
    platform.invokeMethod('encoded', encoded);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: В сервисах и репозиториях
// =============================================================================

class DataService {
  static const platform = MethodChannel('com.example/service');

  // ruleid: platform-channel-injection
  Future<String> sendUserData(String userId, String userInput) async {
    final result = await platform.invokeMethod('process_user', {
      'userId': userId,
      'data': userInput,
    });
    return result;
  }

  // ruleid: platform-channel-injection
  void logUserAction(String action, Map<String, dynamic> parameters) {
    platform.invokeMethod('log_action', {
      'action': action,
      'params': parameters,
    });
  }
}

class UserRepository {
  static const platform = MethodChannel('com.example/repository');

  // ruleid: platform-channel-injection
  Future<void> saveUserPreference(String key, String value) async {
    await platform.invokeMethod('save_pref', {'key': key, 'value': value});
  }

  // ruleid: platform-channel-injection
  Future<String?> getUserData(String field) async {
    return await platform.invokeMethod('get_data', field);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: С множественными каналами
// =============================================================================

class MultiChannelInjection {
  static const channel1 = MethodChannel('com.example/channel1');
  static const channel2 = MethodChannel('com.example/channel2');
  static const channel3 = MethodChannel('com.example/channel3');

  final String userInput;

  MultiChannelInjection(this.userInput);

  // ruleid: platform-channel-injection
  void sendToMultiple() {
    channel1.invokeMethod('test', userInput);
    channel2.invokeMethod('test', userInput);
    channel3.invokeMethod('test', userInput);
  }

  // ruleid: platform-channel-injection
  void sendToDynamic(String channelName) {
    MethodChannel(channelName).invokeMethod('test', userInput);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Санитизированные данные
// =============================================================================

class SanitizedInput {
  static const platform = MethodChannel('com.example/app');

  // ok: platform-channel-injection
  void sendSanitizedString(String input) {
    String sanitized = _sanitize(input);
    platform.invokeMethod('process', sanitized);
  }

  // ok: platform-channel-injection
  void sendWithValidation(String input) {
    if (_isValid(input)) {
      platform.invokeMethod('validated', input);
    }
  }

  // ok: platform-channel-injection
  void sendEscaped(String input) {
    String escaped = _escapeJson(input);
    platform.invokeMethod('escaped', escaped);
  }

  // ok: platform-channel-injection
  void sendWithWhitelist(String input) {
    if (_whitelist.contains(input)) {
      platform.invokeMethod('whitelisted', input);
    }
  }

  // ok: platform-channel-injection
  void sendWithRegexValidation(String input) {
    if (RegExp(r'^[a-zA-Z0-9]+$').hasMatch(input)) {
      platform.invokeMethod('regex_valid', input);
    }
  }

  String _sanitize(String input) {
    return input.replaceAll(RegExp(r'[&]'));
  }

  bool _isValid(String input) {
    return input.length < 100 && !input.contains(RegExp(r'[<>]'));
  }

  String _escapeJson(String input) {
    return jsonEncode(input);
  }

  final List<String> _whitelist = ['read', 'write', 'delete'];
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Константные значения
// =============================================================================

class ConstantValues {
  static const platform = MethodChannel('com.example/app');

  // ok: platform-channel-injection
  void sendConstantString() {
    platform.invokeMethod('get_version');
  }

  // ok: platform-channel-injection
  void sendConstantWithArgs() {
    platform.invokeMethod('initialize', {'apiKey': '123456'});
  }

  // ok: platform-channel-injection
  void sendPredefined() {
    const Map<String, dynamic> config = {
      'mode': 'release',
      'debug': false,
    };
    platform.invokeMethod('configure', config);
  }

  // ok: platform-channel-injection
  void sendEnumValue(ChannelAction action) {
    platform.invokeMethod(action.toString());
  }
}

enum ChannelAction { initialize, start, stop }

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Только чтение, без отправки
// =============================================================================

class ReadOnlyOperations {
  static const platform = MethodChannel('com.example/app');

  // ok: platform-channel-injection
  Future<String> readData() async {
    return await platform.invokeMethod('get_data');
  }

  // ok: platform-channel-injection
  Future<List<dynamic>> fetchList() async {
    return await platform.invokeListMethod('get_list');
  }

  // ok: platform-channel-injection
  Future<Map<String, dynamic>> fetchMap() async {
    return await platform.invokeMapMethod('get_map');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Другие типы каналов
// =============================================================================

class OtherChannels {
  final String userInput;

  OtherChannels(this.userInput);

  // ok: platform-channel-injection
  void basicMessageChannel() {
    const channel = BasicMessageChannel('com.example/messages', StringCodec());
    channel.send(userInput);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Системные вызовы (не пользовательские данные)
// =============================================================================

class SystemCalls {
  static const platform = MethodChannel('com.example/app');

  // ok: platform-channel-injection
  void sendDeviceInfo() {
    platform.invokeMethod('device_info', {
      'platform': 'android',
      'version': '12',
    });
  }

  // ok: platform-channel-injection
  void sendAppState() {
    platform.invokeMethod('app_state', 'background');
  }

  // ok: platform-channel-injection
  void sendTimestamp() {
    platform.invokeMethod('timestamp', DateTime.now().toIso8601String());
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная валидация
// =============================================================================

// ruleid: platform-channel-injection
class PartialValidation {
  static const platform = MethodChannel('com.example/app');

  final String userInput;

  PartialValidation(this.userInput);

  // ruleid: platform-channel-injection
  void sendWithBasicCheck() {
    if (userInput.isNotEmpty) {
      platform.invokeMethod('process', userInput);
    }
  }

  // ruleid: platform-channel-injection
  void sendWithTrim() {
    platform.invokeMethod('process', userInput.trim());
  }

  // ruleid: platform-channel-injection
  void sendWithToLowerCase() {
    platform.invokeMethod('process', userInput.toLowerCase());
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Динамические имена каналов
// =============================================================================

// ruleid: platform-channel-injection
class DynamicChannelName {
  final String channelName;
  final String userInput;

  DynamicChannelName(this.channelName, this.userInput);

  // ruleid: platform-channel-injection
  void sendToDynamicChannel() {
    MethodChannel(channelName).invokeMethod('test', userInput);
  }

  // ruleid: platform-channel-injection
  void sendWithDynamicMethod() {
    const platform = MethodChannel('com.example/app');
    String methodName = 'process_${userInput.substring(0, 5)}';
    platform.invokeMethod(methodName);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: В асинхронных цепочках
// =============================================================================

// ruleid: platform-channel-injection
class AsyncChainInjection {
  static const platform = MethodChannel('com.example/app');

  final String userInput;

  AsyncChainInjection(this.userInput);

  // ruleid: platform-channel-injection
  Future<void> asyncChain() async {
    await Future.delayed(const Duration(seconds: 1));
    final processed = await _process(userInput);
    await platform.invokeMethod('async_result', processed);
  }

  // ruleid: platform-channel-injection
  void thenChain() {
    Future.value(userInput)
        .then((value) => value.toUpperCase())
        .then((value) => platform.invokeMethod('then_result', value));
  }

  Future<String> _process(String input) async {
    return input.trim();
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: В колбэках платформы
// =============================================================================

// ruleid: platform-channel-injection
class PlatformCallbackInjection {
  static const platform = MethodChannel('com.example/app');

  void setupCallbacks() {
    platform.setMethodCallHandler((call) async {
      if (call.method == 'user_input') {
        String? userData = call.arguments as String?;
        if (userData != null) {
          // ruleid: platform-channel-injection
          platform.invokeMethod('process_user_input', userData);
        }
      }
      return null;
    });
  }
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полный жизненный цикл
// =============================================================================

// ruleid: platform-channel-injection
class UserDataChannelManager {
  static const platform = MethodChannel('com.example/user_data');
  
  String? _cachedUserInput;

  // ruleid: platform-channel-injection
  Future<void> processUserInput(String input) async {
    _cachedUserInput = input;
    
    if (!_validateLocally(input)) {
      return;
    }

    try {
      final result = await platform.invokeMethod('validate_and_process', {
        'input': input,
        'timestamp': DateTime.now().toIso8601String(),
        'source': 'user_form',
      });

      if (result == 'success') {
        // ruleid: platform-channel-injection
        await platform.invokeMethod('save', {
          'data': input,
          'user_id': await _getUserId(),
        });
      }
    } on PlatformException catch (e) {
      print('Error: $e');
    }
  }

  bool _validateLocally(String input) {
    return input.isNotEmpty && input.length < 1000;
  }

  Future<String> _getUserId() async {
    return 'user_123';
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации синтаксиса
// =============================================================================

class SyntaxVariations {
  static const platform = MethodChannel('com.example/app');
  final String userInput;

  SyntaxVariations(this.userInput);

  // ruleid: platform-channel-injection
  void test1() {
    platform.invokeMethod('test', userInput);
  }

  // ruleid: platform-channel-injection
  void test2() {
    platform.invokeMethod('test', {'key': userInput});
  }

  // ruleid: platform-channel-injection
  void test3() {
    platform.invokeMethod('test', [userInput, 'static']);
  }

  // ruleid: platform-channel-injection
  void test4() {
    platform.invokeMethod(userInput);
  }

  // ruleid: platform-channel-injection
  void test5() {
    platform.invokeMethod('test', {'nested': {'value': userInput}});
  }

  // ok: platform-channel-injection
  void test6() {
    platform.invokeMethod('test', 'static value');
  }

  // ok: platform-channel-injection
  void test7() {
    platform.invokeMethod('test');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Комментарии и строки
// =============================================================================

void testNonCode() {
  // ok: platform-channel-injection
  String comment = 'platform.invokeMethod("process", userInput)';
  
  // ok: platform-channel-injection
  String doc = '''
    Example of unsafe usage:
    platform.invokeMethod('process', userInput);
  ''';
  
  // ok: platform-channel-injection
  Map<String, String> config = {
    'channel': 'MethodChannel',
    'method': 'invokeMethod',
  };
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

// Для имитации внешних источников
Future<String> fetchFromApi() async => 'api_response';
Future<String> queryDatabase() async => 'db_data';
Future<String> readFile() async => 'file_content';
Future<String> getSharedPrefs() async => 'pref_value';