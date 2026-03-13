// test_isolate_injection.dart
// Тест для правила: isolate-message-injection
// Правило ищет небезопасную передачу данных между изолятами
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:isolate';
import 'dart:convert';
import 'package:json_schema/json_schema.dart';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасная передача пользовательских данных в изоляты
// =============================================================================

class UnsafeIsolateSpawn {
  void testUnsafeSpawn(String userInput) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_processData, userInput);
  }

  void testUnsafeSpawnWithMap(Map<String, dynamic> userData) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_processMap, userData);
  }

  void testUnsafeSpawnWithList(List<String> userList) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_processList, userList);
  }

  void testUnsafeSpawnWithJson(String jsonString) {
    var data = jsonDecode(jsonString);
    // ruleid: isolate-message-injection
    Isolate.spawn(_processData, data);
  }

  static void _processData(dynamic message) {
    print('Processing: $message');
  }

  static void _processMap(Map<String, dynamic> message) {
    print('Processing map: $message');
  }

  static void _processList(List<dynamic> message) {
    print('Processing list: $message');
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасная передача через SendPort
// =============================================================================

class UnsafeSendPort {
  late SendPort _sendPort;

  void testUnsafeSend(String userInput) {
    // ruleid: isolate-message-injection
    _sendPort.send(userInput);
  }

  void testUnsafeSendMap(Map<String, dynamic> userData) {
    // ruleid: isolate-message-injection
    _sendPort.send(userData);
  }

  void testUnsafeSendList(List<dynamic> userList) {
    // ruleid: isolate-message-injection
    _sendPort.send(userList);
  }

  void testUnsafeSendRawJson(String jsonString) {
    // ruleid: isolate-message-injection
    _sendPort.send(jsonString);
  }

  void testUnsafeSendComplex(Map<String, dynamic> userData) {
    // ruleid: isolate-message-injection
    _sendPort.send({
      'type': 'user_action',
      'data': userData,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасная обработка в ReceivePort
// =============================================================================

class UnsafeReceivePort {
  late ReceivePort _receivePort;

  void setupReceiver() {
    _receivePort = ReceivePort();
    
    // ruleid: isolate-message-injection
    _receivePort.listen((message) {
      // Прямая обработка без проверки
      _processMessage(message);
    });
  }

  void testUnsafeListener() {
    // ruleid: isolate-message-injection
    _receivePort.listen((message) {
      if (message is Map) {
        _executeCommand(message);
      }
    });
  }

  void testUnsafeFirst() {
    // ruleid: isolate-message-injection
    _receivePort.first.then((message) {
      _handleUnsafeMessage(message);
    });
  }

  void testUnsafeTake() {
    // ruleid: isolate-message-injection
    _receivePort.take(5).listen((message) {
      _processUnsafeData(message);
    });
  }

  void _processMessage(dynamic msg) {
    // Небезопасная обработка
    if (msg is Map && msg.containsKey('command')) {
      _runCommand(msg['command']);
    }
  }

  void _executeCommand(Map cmd) {
    print('Executing: $cmd');
  }

  void _handleUnsafeMessage(dynamic msg) {
    print('Handling: $msg');
  }

  void _processUnsafeData(dynamic data) {
    print('Processing: $data');
  }

  void _runCommand(dynamic cmd) {
    print('Running: $cmd');
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасное использование RawReceivePort
// =============================================================================

class UnsafeRawReceivePort {
  void testUnsafeRawPort() {
    final RawReceivePort port = RawReceivePort();
    // ruleid: isolate-message-injection
    port.handler = (message) {
      _processRawMessage(message);
    };
  }

  void testUnsafeRawPortWithCallback() {
    // ruleid: isolate-message-injection
    final RawReceivePort port = RawReceivePort((message) {
      _executeRawCommand(message);
    });
  }

  void _processRawMessage(dynamic message) {
    if (message is String) {
      print('Processing raw: $message');
    }
  }

  void _executeRawCommand(dynamic cmd) {
    if (cmd is Map && cmd.containsKey('code')) {
      print('Executing command with code: ${cmd['code']}');
    }
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Передача между изолятами без валидации
// =============================================================================

class IsolateCommunication {
  late String userInput;

  Future<void> spawnAndSend(String input) async {
    userInput = input;
    final ReceivePort receivePort = ReceivePort();
    // ruleid: isolate-message-injection
    await Isolate.spawn(_isolateEntry, receivePort.sendPort);
    
    final SendPort sendPort = await receivePort.first as SendPort;
    
    // ruleid: isolate-message-injection
    sendPort.send(userInput);
  }

  void testTwoWayCommunication() {
    final ReceivePort receivePort = ReceivePort();
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is SendPort) {
        // ruleid: isolate-message-injection
        message.send({'command': 'execute', 'payload': userInput});
      } else {
        // ruleid: isolate-message-injection
        _processResponse(message);
      }
    });
    
    // ruleid: isolate-message-injection
    Isolate.spawn(_isolateWithCallback, receivePort.sendPort);
  }

  static void _isolateEntry(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      _handleMessage(message);
    });
  }

  static void _isolateWithCallback(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      _processAndRespond(message, sendPort);
    });
  }

  static void _handleMessage(dynamic msg) {
    print('Got: $msg');
  }

  static void _processAndRespond(dynamic msg, SendPort replyTo) {
    // ruleid: isolate-message-injection
    replyTo.send('Processed: $msg');
  }

  void _processResponse(dynamic response) {
    print('Response: $response');
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Передача функций и замыканий
// =============================================================================

class UnsafeFunctionPassing {
  void testSendFunction() {
    final ReceivePort receivePort = ReceivePort();
    // ruleid: isolate-message-injection
    Isolate.spawn(_isolateWithFunction, receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is SendPort) {
        // ruleid: isolate-message-injection
        message.send('function');
      }
    });
  }

  void testSendClosure() {
    final ReceivePort receivePort = ReceivePort();
    int localVar = 42;
    
    // ruleid: isolate-message-injection
    Isolate.spawn(_isolateWithClosure, receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is SendPort) {
        // ruleid: isolate-message-injection
        message.send(localVar.toString());
      }
    });
  }

  static void _isolateWithFunction(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is String) {
        print('Got message: $message');
      }
    });
  }

  static void _isolateWithClosure(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is String) {
        print('Got closure message: $message');
      }
    });
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Десериализация непроверенных данных
// =============================================================================

class UnsafeDeserialization {
  void testJsonDeserialize(String jsonString) {
    final ReceivePort receivePort = ReceivePort();
    // ruleid: isolate-message-injection
    Isolate.spawn(_isolateWithJson, receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is SendPort) {
        var data = jsonDecode(jsonString);
        // ruleid: isolate-message-injection
        message.send(data);
      }
    });
  }

  void testComplexDeserialize(String base64Data) {
    final ReceivePort receivePort = ReceivePort();
    // ruleid: isolate-message-injection
    Isolate.spawn(_isolateWithBinary, receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is SendPort) {
        List<int> bytes = base64Decode(base64Data);
        String data = utf8.decode(bytes);
        // ruleid: isolate-message-injection
        message.send(jsonDecode(data));
      }
    });
  }

  static void _isolateWithJson(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      if (message is Map) {
        _processJsonMap(message);
      }
    });
  }

  static void _isolateWithBinary(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      _processBinaryData(message);
    });
  }

  static void _processJsonMap(Map map) {
    print('Processing: $map');
  }

  static void _processBinaryData(dynamic data) {
    print('Processing binary: $data');
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Множественные изоляты без валидации
// =============================================================================

class MultipleIsolatesUnsafe {
  List<Isolate> _isolates = [];
  List<SendPort> _ports = [];

  Future<void> spawnMultiple(int count, String userInput) async {
    for (int i = 0; i < count; i++) {
      final ReceivePort receivePort = ReceivePort();
      // ruleid: isolate-message-injection
      final Isolate isolate = await Isolate.spawn(_workerIsolate, receivePort.sendPort);
      _isolates.add(isolate);
      
      final SendPort sendPort = await receivePort.first as SendPort;
      _ports.add(sendPort);
      
      // ruleid: isolate-message-injection
      sendPort.send({'id': i, 'data': userInput});
    }
  }

  void broadcastToAll(dynamic message) {
    for (SendPort port in _ports) {
      // ruleid: isolate-message-injection
      port.send(message);
    }
  }

  static void _workerIsolate(SendPort sendPort) {
    final ReceivePort receivePort = ReceivePort();
    sendPort.send(receivePort.sendPort);
    
    // ruleid: isolate-message-injection
    receivePort.listen((message) {
      print('Worker got: $message');
    });
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасные паттерны в UI изолятах
// =============================================================================

class UnsafeUIIsolates {
  void spawnComputeIsolate(String userCode) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_computeIntensive, userCode);
  }

  void spawnBackgroundTask(Map<String, dynamic> task) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_backgroundWorker, task);
  }

  void spawnNetworkIsolate(String url, Map<String, String> headers) {
    // ruleid: isolate-message-injection
    Isolate.spawn(_networkRequest, {'url': url, 'headers': headers});
  }

  static void _computeIntensive(String code) {
    print('Computing with code: $code');
  }

  static void _backgroundWorker(Map task) {
    if (task['type'] == 'process') {
      _processTask(task['data']);
    }
  }

  static void _networkRequest(Map params) {
    print('Request to: ${params['url']}');
  }

  static void _processTask(dynamic data) {
    print('Processing: $data');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная передача с валидацией схемы
// =============================================================================

class SafeIsolateWithSchema {
  late JsonSchema _messageSchema;
  
  SafeIsolateWithSchema() {
    Map<String, dynamic> schema = {
      'type': 'object',
      'properties': {
        'command': {'type': 'string', 'enum': ['process', 'compute']},
        'data': {'type': 'string', 'maxLength': 1000},
        'timestamp': {'type': 'string', 'format': 'date-time'},
      },
      'required': ['command', 'data'],
      'additionalProperties': false,
    };
    _messageSchema = JsonSchema.create(schema);
  }

  Future<void> spawnWithValidation(String userInput) async {
    try {
      Map<String, dynamic> message = jsonDecode(userInput);
      if (_validateMessage(message)) {
        // ok: isolate-message-injection
        await Isolate.spawn(_safeIsolate, message);
      }
    } catch (e) {
      print('Invalid message: $e');
    }
  }

  void sendWithValidation(SendPort port, Map<String, dynamic> message) {
    if (_validateMessage(message)) {
      // ok: isolate-message-injection
      port.send(message);
    }
  }

  bool _validateMessage(Map<String, dynamic> message) {
    try {
      return _messageSchema.validate(message);
    } catch (e) {
      return false;
    }
  }

  static void _safeIsolate(Map<String, dynamic> message) {
    print('Processing validated: $message');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная передача с типизацией
// =============================================================================

class SafeTypedMessages {
  void spawnWithTypedData(String userInput) {
    SafeMessage safeData = SafeMessage.fromUserInput(userInput);
    if (safeData.isValid) {
      // ok: isolate-message-injection
      Isolate.spawn(_typedIsolate, safeData.toJson());
    }
  }

  void sendWithTypeCheck(SendPort port, dynamic message) {
    if (message is Map<String, dynamic>) {
      try {
        SafeMessage safeMsg = SafeMessage.fromJson(message);
        if (safeMsg.isValid) {
          // ok: isolate-message-injection
          port.send(safeMsg.toJson());
        }
      } catch (e) {
        print('Type error: $e');
      }
    }
  }

  static void _typedIsolate(Map<String, dynamic> message) {
    try {
      SafeMessage safeMsg = SafeMessage.fromJson(message);
      if (safeMsg.isValid) {
        print('Processing: ${safeMsg.data}');
      }
    } catch (e) {
      print('Invalid message');
    }
  }
}

class SafeMessage {
  final String command;
  final String data;
  final DateTime timestamp;
  final bool isValid;

  SafeMessage({required this.command, required this.data, DateTime? timestamp})
      : timestamp = timestamp ?? DateTime.now(),
        isValid = command.isNotEmpty && data.length <= 1000;

  factory SafeMessage.fromUserInput(String input) {
    try {
      Map<String, dynamic> json = jsonDecode(input);
      if (json.containsKey('command') && json.containsKey('data')) {
        return SafeMessage(
          command: json['command'].toString(),
          data: json['data'].toString(),
          timestamp: json['timestamp'] != null 
              ? DateTime.parse(json['timestamp'].toString()) 
              : null,
        );
      }
    } catch (_) {}
    return SafeMessage(command: '', data: '');
  }

  factory SafeMessage.fromJson(Map<String, dynamic> json) {
    return SafeMessage(
      command: json['command']?.toString() ?? '',
      data: json['data']?.toString() ?? '',
      timestamp: json['timestamp'] != null 
          ? DateTime.parse(json['timestamp'].toString()) 
          : null,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'command': command,
      'data': data,
      'timestamp': timestamp.toIso8601String(),
    };
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная передача с whitelist команд
// =============================================================================

class SafeCommandWhitelist {
  static const Set<String> ALLOWED_COMMANDS = {'process', 'compute', 'analyze'};
  
  void spawnWithWhitelist(Map<String, dynamic> message) {
    if (message.containsKey('command') && 
        ALLOWED_COMMANDS.contains(message['command'])) {
      
      if (_validateData(message['data'])) {
        // ok: isolate-message-injection
        Isolate.spawn(_whitelistedIsolate, message);
      }
    }
  }

  void sendWithWhitelist(SendPort port, String command, dynamic data) {
    if (ALLOWED_COMMANDS.contains(command) && _validateData(data)) {
      // ok: isolate-message-injection
      port.send({'command': command, 'data': data});
    }
  }

  static bool _validateData(dynamic data) {
    if (data is String) {
      return data.length <= 1000 && !data.contains(RegExp(r'[<>$(){}]'));
    }
    if (data is Map) {
      return jsonEncode(data).length <= 5000;
    }
    return false;
  }

  static void _whitelistedIsolate(Map<String, dynamic> message) {
    String command = message['command'];
    dynamic data = message['data'];
    print('Executing $command with $data');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная передача с проверкой границ
// =============================================================================

class SafeBoundaryChecks {
  static const int MAX_MESSAGE_SIZE = 1024 * 10;
  static const int MAX_DEPTH = 5;

  void spawnWithSizeCheck(dynamic message) {
    int size = estimateSize(message);
    if (size <= MAX_MESSAGE_SIZE && checkDepth(message) <= MAX_DEPTH) {
      // ok: isolate-message-injection
      Isolate.spawn(_boundedIsolate, message);
    }
  }

  void sendWithBounds(SendPort port, dynamic message) {
    if (estimateSize(message) <= MAX_MESSAGE_SIZE) {
      // ok: isolate-message-injection
      port.send(message);
    }
  }

  static int estimateSize(dynamic obj) {
    try {
      return utf8.encode(jsonEncode(obj)).length;
    } catch (_) {
      return 0;
    }
  }

  static int checkDepth(dynamic obj, [int depth = 0]) {
    if (depth > MAX_DEPTH) return depth;
    
    if (obj is Map) {
      int maxDepth = depth;
      obj.forEach((key, value) {
        int childDepth = checkDepth(value, depth + 1);
        if (childDepth > maxDepth) maxDepth = childDepth;
      });
      return maxDepth;
    }
    
    if (obj is List) {
      int maxDepth = depth;
      for (var item in obj) {
        int childDepth = checkDepth(item, depth + 1);
        if (childDepth > maxDepth) maxDepth = childDepth;
      }
      return maxDepth;
    }
    
    return depth;
  }

  static void _boundedIsolate(dynamic message) {
    print('Processing bounded message');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасная передача через изолированные типы
// =============================================================================

class SafeTransferObject {
  final String id;
  final String type;
  final String payload;
  final DateTime createdAt;

  const SafeTransferObject({
    required this.id,
    required this.type,
    required this.payload,
    required this.createdAt,
  });

  bool get isValid {
    return id.isNotEmpty && 
           type.isNotEmpty && 
           payload.length <= 1000 &&
           createdAt.isBefore(DateTime.now());
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'type': type,
      'payload': payload,
      'createdAt': createdAt.toIso8601String(),
    };
  }

  factory SafeTransferObject.fromJson(Map<String, dynamic> json) {
    try {
      return SafeTransferObject(
        id: json['id']?.toString() ?? '',
        type: json['type']?.toString() ?? '',
        payload: json['payload']?.toString() ?? '',
        createdAt: DateTime.parse(json['createdAt']?.toString() ?? ''),
      );
    } catch (_) {
      return SafeTransferObject(
        id: '',
        type: '',
        payload: '',
        createdAt: DateTime.now(),
      );
    }
  }
}

class SafeTypedTransfer {
  void spawnWithTransferObject(SafeTransferObject obj) {
    if (obj.isValid) {
      // ok: isolate-message-injection
      Isolate.spawn(_typedObjectIsolate, obj.toJson());
    }
  }

  void sendWithTransferObject(SendPort port, SafeTransferObject obj) {
    if (obj.isValid) {
      // ok: isolate-message-injection
      port.send(obj.toJson());
    }
  }

  void receiveWithTransferObject(dynamic message) {
    if (message is Map<String, dynamic>) {
      SafeTransferObject obj = SafeTransferObject.fromJson(message);
      if (obj.isValid) {
        _processTransferObject(obj);
      }
    }
  }

  static void _typedObjectIsolate(Map<String, dynamic> message) {
    if (message is Map) {
      SafeTransferObject obj = SafeTransferObject.fromJson(message.cast<String, dynamic>());
      if (obj.isValid) {
        print('Processing: ${obj.payload}');
      }
    }
  }

  void _processTransferObject(SafeTransferObject obj) {
    print('Got ${obj.type}: ${obj.payload}');
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная валидация
// =============================================================================

class PartialValidationIsolate {
  void spawnWithPartialValidation(String userInput) {
    if (userInput.length < 10000) {
      // ruleid: isolate-message-injection
      Isolate.spawn(_partialIsolate, userInput);
    }
  }

  void sendWithPartialValidation(SendPort port, Map data) {
    if (data.containsKey('command')) {
      // ruleid: isolate-message-injection
      port.send(data);
    }
  }

  void receiveWithPartialValidation(dynamic message) {
    if (message is Map) {
      _processPartial(message);
    }
  }

  static void _partialIsolate(dynamic message) {
    print('Got: $message');
  }

  void _processPartial(Map msg) {
    if (msg['command'] == 'eval') {
      print('Evaluating: ${msg['code']}');
    }
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Передача через каналы с частичной валидацией
// =============================================================================

class PartialChannelValidation {
  final ReceivePort _receivePort = ReceivePort();
  late final SendPort _sendPort;

  PartialChannelValidation() {
    // ruleid: isolate-message-injection
    _receivePort.listen(_handleMessage);
  }

  void setup(SendPort port) {
    _sendPort = port;
  }

  void _handleMessage(dynamic message) {
    if (message is Map) {
      _processMessage(message);
    } else if (message is String) {
      _processString(message);
    } else if (message is List) {
      _processList(message);
    }
  }

  void sendMessage(dynamic message) {
    // ruleid: isolate-message-injection
    _sendPort.send(message);
  }

  void _processMessage(Map msg) {
    print('Processing map: $msg');
  }

  void _processString(String msg) {
    if (msg.startsWith('cmd:')) {
      String cmd = msg.substring(4);
      _executeCommand(cmd);
    }
  }

  void _processList(List msg) {
    print('Processing list: $msg');
  }

  void _executeCommand(String cmd) {
    print('Executing: $cmd');
  }
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

String userInput = '{"command": "eval", "code": "malicious()"}';