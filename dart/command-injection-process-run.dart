// test_command_injection.dart
// Тест для правила: command-injection-process-run
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:io';
import 'package:path/path.dart' as path;

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: command-injection-process-run
const String SAFE_COMMAND = 'ls';

// ok: command-injection-process-run
const String SAFE_ARGUMENT = '-la';

// ok: command-injection-process-run
const String TRUSTED_PATH = '/usr/local/bin/app';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Process.run с интерполяцией команд
// =============================================================================

// ruleid: command-injection-process-run
final vulnerable1 = await Process.run('ls', ['$userInput']);

// ruleid: command-injection-process-run
final vulnerable2 = await Process.run('echo', [userInput]);

// ruleid: command-injection-process-run
final vulnerable3 = await Process.run('cat', ['$filePath']);

Future<void> testProcessRunInjection(String userInput, String filePath) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('ls', [userInput]);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('cat', ['$filePath']);

  // ruleid: command-injection-process-run
  final result3 = await Process.run('grep', [searchTerm, fileName]);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Process.run с shell=true (критично!)
// =============================================================================

// ruleid: command-injection-process-run
final shellVulnerable1 = await Process.run('ls $userInput', [], runInShell: true);

// ruleid: command-injection-process-run
final shellVulnerable2 = await Process.run('cat $filePath', [], runInShell: true);

// ruleid: command-injection-process-run
final shellVulnerable3 = await Process.run('echo $message | grep test', [], runInShell: true);

Future<void> testShellInjection(String userInput, String filePath, String message) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('ls $userInput', [], runInShell: true);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('cat $filePath', [], runInShell: true);

  // ruleid: command-injection-process-run
  final result3 = await Process.run('echo $message | grep test', [], runInShell: true);

  // ruleid: command-injection-process-run
  final result4 = await Process.run('rm -rf $directory', [], runInShell: true);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Process.start с интерполяцией
// =============================================================================

// ruleid: command-injection-process-run
final startVulnerable1 = await Process.start('ls', [userInput]);

// ruleid: command-injection-process-run
final startVulnerable2 = await Process.start('cat', ['$filePath']);

Future<void> testProcessStartInjection(String userInput, String filePath) async {
  // ruleid: command-injection-process-run
  final process1 = await Process.start('ls', [userInput]);

  // ruleid: command-injection-process-run
  final process2 = await Process.start('cat', ['$filePath']);

  // ruleid: command-injection-process-run
  final process3 = await Process.start('grep', [searchTerm, fileName]);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Process.start с shell=true
// =============================================================================

// ruleid: command-injection-process-run
final startShellVulnerable1 = await Process.start('ls $userInput', [], runInShell: true);

// ruleid: command-injection-process-run
final startShellVulnerable2 = await Process.start('cat $filePath', [], runInShell: true);

Future<void> testStartShellInjection(String userInput, String filePath) async {
  // ruleid: command-injection-process-run
  final process1 = await Process.start('ls $userInput', [], runInShell: true);

  // ruleid: command-injection-process-run
  final process2 = await Process.start('cat $filePath', [], runInShell: true);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Конкатенация строк в командах
// =============================================================================

// ruleid: command-injection-process-run
final concatVulnerable1 = await Process.run('ls', ['-la ' + userInput]);

// ruleid: command-injection-process-run
final concatVulnerable2 = await Process.run('cat', [filePath + '.txt']);

// ruleid: command-injection-process-run
final concatVulnerable3 = await Process.run('echo', ['Hello ' + userName]);

Future<void> testConcatInjection(String userInput, String filePath, String userName) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('ls', ['-la ' + userInput]);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('cat', [filePath + '.txt']);

  // ruleid: command-injection-process-run
  final result3 = await Process.run('echo', ['Hello ' + userName]);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамическое построение команд
// =============================================================================

// ruleid: command-injection-process-run
final dynamicVulnerable1 = await Process.run(command, [arg1, arg2]);

// ruleid: command-injection-process-run
final dynamicVulnerable2 = await Process.run('ls', arguments);

Future<void> testDynamicInjection(String command, List<String> arguments, String arg1, String arg2) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run(command, [arg1, arg2]);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('ls', arguments);

  // ruleid: command-injection-process-run
  final result3 = await Process.run(getCommand(), getArguments());
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Опасные команды с пользовательским вводом
// =============================================================================

// ruleid: command-injection-process-run
final dangerousCmd1 = await Process.run('rm', [filePath]);

// ruleid: command-injection-process-run
final dangerousCmd2 = await Process.run('curl', [url]);

// ruleid: command-injection-process-run
final dangerousCmd3 = await Process.run('wget', [url]);

// ruleid: command-injection-process-run
final dangerousCmd4 = await Process.run('bash', ['-c', userScript]);

// ruleid: command-injection-process-run
final dangerousCmd5 = await Process.run('sh', ['-c', userScript]);

Future<void> testDangerousCommands(String filePath, String url, String userScript) async {
  // ruleid: command-injection-process-run
  await Process.run('rm', [filePath]);

  // ruleid: command-injection-process-run
  await Process.run('curl', [url]);

  // ruleid: command-injection-process-run
  await Process.run('wget', [url]);

  // ruleid: command-injection-process-run
  await Process.run('bash', ['-c', userScript]);

  // ruleid: command-injection-process-run
  await Process.run('sh', ['-c', userScript]);

  // ruleid: command-injection-process-run
  await Process.run('eval', [userInput]);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Классы и методы с уязвимостями
// =============================================================================

class CommandExecutor {
  // ruleid: command-injection-process-run
  Future<ProcessResult> execute(String command, List<String> args) async {
    return await Process.run(command, args);
  }

  // ruleid: command-injection-process-run
  Future<ProcessResult> executeFile(String filePath) async {
    return await Process.run('cat', [filePath]);
  }

  // ruleid: command-injection-process-run
  Future<ProcessResult> executeShell(String command) async {
    return await Process.run(command, [], runInShell: true);
  }

  // ruleid: command-injection-process-run
  Future<Process> startProcess(String command, List<String> args) async {
    return await Process.start(command, args);
  }
}

// ruleid: command-injection-process-run
class UnsafeFileReader {
  // ruleid: command-injection-process-run
  Future<String> readFile(String path) async {
    final result = await Process.run('cat', [path]);
    return result.stdout.toString();
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Комбинированные уязвимости
// =============================================================================

// ruleid: command-injection-process-run
final combinedVulnerable1 = await Process.run('bash', ['-c', 'cat $filePath | grep $searchTerm']);

// ruleid: command-injection-process-run
final combinedVulnerable2 = await Process.run('sh', ['-c', 'ls $directory && cat $file']);

Future<void> testCombinedInjection(String filePath, String searchTerm, String directory, String file) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('bash', ['-c', 'cat $filePath | grep $searchTerm']);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('sh', ['-c', 'ls $directory && cat $file']);

  // ruleid: command-injection-process-run
  final result3 = await Process.run('bash', ['-c', 'curl $url | bash']);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Пайплайны и цепочки команд
// =============================================================================

// ruleid: command-injection-process-run
final pipelineVulnerable1 = await Process.run('ls', ['$dir | grep $pattern']);

// ruleid: command-injection-process-run
final pipelineVulnerable2 = await Process.run('cat', ['$file | head -n 10']);

Future<void> testPipelineInjection(String dir, String pattern, String file) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('ls', ['$dir | grep $pattern']);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('cat', ['$file | head -n 10']);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Условное выполнение команд
// =============================================================================

// ruleid: command-injection-process-run
final conditionalVulnerable1 = await Process.run(useSudo ? 'sudo $command' : command, args);

// ruleid: command-injection-process-run
final conditionalVulnerable2 = await Process.run('ls', condition ? [userInput] : ['-la']);

Future<void> testConditionalInjection(String command, List<String> args, String userInput, bool useSudo, bool condition) async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run(useSudo ? 'sudo $command' : command, args);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('ls', condition ? [userInput] : ['-la']);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Циклы с командами
// =============================================================================

// ruleid: command-injection-process-run
Future<void> testLoopInjection(List<String> files) async {
  for (var file in files) {
    // ruleid: command-injection-process-run
    await Process.run('cat', [file]);
  }
}

// ruleid: command-injection-process-run
Future<void> testMapInjection(List<String> commands) async {
  // ruleid: command-injection-process-run
  final results = await Future.wait(commands.map((cmd) => Process.run(cmd, [])));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасное использование Process.run
// =============================================================================

// ok: command-injection-process-run
final safe1 = await Process.run('ls', ['-la']);

// ok: command-injection-process-run
final safe2 = await Process.run('cat', ['/etc/hosts']);

// ok: command-injection-process-run
final safe3 = await Process.run('echo', ['Hello World']);

Future<void> testSafeProcessRun() async {
  // ok: command-injection-process-run
  final result1 = await Process.run('ls', ['-la']);

  // ok: command-injection-process-run
  final result2 = await Process.run('cat', ['/etc/hosts']);

  // ok: command-injection-process-run
  final result3 = await Process.run('echo', ['Hello World']);

  // ok: command-injection-process-run
  final result4 = await Process.run('date', []);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Валидация и санитизация ввода
// =============================================================================

// ok: command-injection-process-run
Future<void> testValidatedInput(String userInput) async {
  // ok: command-injection-process-run
  if (!RegExp(r'^[a-zA-Z0-9_-]+$').hasMatch(userInput)) return;
  // ok: command-injection-process-run
  final result = await Process.run('ls', [userInput]);
}

// ok: command-injection-process-run
Future<void> testSanitizedInput(String userInput) async {
  // ok: command-injection-process-run
  final sanitized = userInput.replaceAll(RegExp(r'[;&|`$]'), '');
  // ok: command-injection-process-run
  final result = await Process.run('ls', [sanitized]);
}

// ok: command-injection-process-run
Future<void> testWhitelistInput(String userInput) async {
  // ok: command-injection-process-run
  const allowed = ['file1.txt', 'file2.txt', 'file3.txt'];
  // ok: command-injection-process-run
  if (!allowed.contains(userInput)) return;
  // ok: command-injection-process-run
  final result = await Process.run('cat', [userInput]);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные классы и методы
// =============================================================================

class SafeCommandExecutor {
  // ok: command-injection-process-run
  Future<ProcessResult> execute(String command, List<String> args) async {
    // ok: command-injection-process-run
    const allowedCommands = ['ls', 'cat', 'echo'];
    // ok: command-injection-process-run
    if (!allowedCommands.contains(command)) throw ArgumentError('Command not allowed');
    return await Process.run(command, args);
  }

  // ok: command-injection-process-run
  Future<ProcessResult> executeFile(String filePath) async {
    // ok: command-injection-process-run
    if (!filePath.startsWith('/safe/path/')) throw ArgumentError('Path not allowed');
    return await Process.run('cat', [filePath]);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование безопасных альтернатив
// =============================================================================

// ok: command-injection-process-run
Future<void> testSafeFileRead(String filePath) async {
  // ok: command-injection-process-run
  final content = await File(filePath).readAsString();
}

// ok: command-injection-process-run
Future<void> testSafeFileWrite(String filePath, String content) async {
  // ok: command-injection-process-run
  await File(filePath).writeAsString(content);
}

// ok: command-injection-process-run
Future<void> testSafeDirectoryList(String dirPath) async {
  // ok: command-injection-process-run
  final entities = await Directory(dirPath).list().toList();
}

// ok: command-injection-process-run
Future<void> testSafeHttpClient(String url) async {
  // ok: command-injection-process-run
  final response = await HttpClient().getUrl(Uri.parse(url));
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная валидация
// =============================================================================

// ruleid: command-injection-process-run
Future<void> testPartialValidation(String userInput) async {
  // ok: command-injection-process-run (эта проверка безопасна)
  if (userInput.isEmpty) return;
  // ruleid: command-injection-process-run (но команда всё ещё уязвима)
  await Process.run('ls', [userInput]);
}

// ruleid: command-injection-process-run
Future<void> testIncompleteSanitization(String userInput) async {
  // ruleid: command-injection-process-run (неполная санитизация)
  final sanitized = userInput.replaceAll(';', '');
  // ruleid: command-injection-process-run
  await Process.run('ls', [sanitized]);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Пути и файлы
// =============================================================================

// ruleid: command-injection-process-run
final pathVulnerable1 = await Process.run('cat', [userPath]);

// ruleid: command-injection-process-run
final pathVulnerable2 = await Process.run('ls', [Directory.current.path + '/' + userInput]);

// ok: command-injection-process-run
Future<void> testSafePath(String userInput) async {
  // ok: command-injection-process-run
  final safePath = path.normalize(userInput);
  // ok: command-injection-process-run
  if (!safePath.startsWith('/allowed/')) return;
  // ok: command-injection-process-run
  await Process.run('cat', [safePath]);
}

// ok: command-injection-process-run
Future<void> testSafePathJoin(String userInput) async {
  // ok: command-injection-process-run
  final safePath = path.join('/allowed', userInput);
  // ok: command-injection-process-run
  if (!path.isWithin('/allowed', safePath)) return;
  // ok: command-injection-process-run
  await File(safePath).readAsString();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Переменные окружения
// =============================================================================

// ruleid: command-injection-process-run
final envVulnerable1 = await Process.run('echo', [Platform.environment['USER_INPUT']]);

// ruleid: command-injection-process-run
final envVulnerable2 = await Process.run('ls', [envVar]);

Future<void> testEnvInjection() async {
  // ruleid: command-injection-process-run
  final result1 = await Process.run('echo', [Platform.environment['USER_INPUT']]);

  // ruleid: command-injection-process-run
  final result2 = await Process.run('ls', [Platform.environment['PATH_INPUT']]);
}

// ok: command-injection-process-run
Future<void> testSafeEnvUsage() async {
  // ok: command-injection-process-run
  final homeDir = Platform.environment['HOME'] ?? '/tmp';
  // ok: command-injection-process-run
  await Directory(homeDir).list().toList();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Асинхронные паттерны
// =============================================================================

// ruleid: command-injection-process-run
Stream<ProcessResult> testStreamInjection(List<String> commands) async* {
  for (var cmd in commands) {
    // ruleid: command-injection-process-run
    yield await Process.run(cmd, []);
  }
}

// ruleid: command-injection-process-run
Future<void> testFutureInjection(String command) async {
  // ruleid: command-injection-process-run
  final result = await Process.run(command, []).timeout(Duration(seconds: 10));
}

// ok: command-injection-process-run
Stream<ProcessResult> testSafeStream() async* {
  const commands = ['ls -la', 'date', 'pwd'];
  for (var cmd in commands) {
    // ok: command-injection-process-run
    final parts = cmd.split(' ');
    // ok: command-injection-process-run
    yield await Process.run(parts[0], parts.skip(1).toList());
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Транзакции и батчи (аналогия)
// =============================================================================

// ruleid: command-injection-process-run
Future<void> testBatchInjection(List<String> files) async {
  for (var file in files) {
    // ruleid: command-injection-process-run
    await Process.run('cat', [file]);
  }
}

// ok: command-injection-process-run
Future<void> testSafeBatch(List<String> files) async {
  for (var file in files) {
    // ok: command-injection-process-run
    if (!file.endsWith('.txt')) continue;
    // ok: command-injection-process-run
    await File(file).readAsString();
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Рекурсивные вызовы
// =============================================================================

// ruleid: command-injection-process-run
Future<void> testRecursiveInjection(String dir) async {
  // ruleid: command-injection-process-run
  final result = await Process.run('ls', [dir]);
  // ruleid: command-injection-process-run
  for (var line in result.stdout.toString().split('\n')) {
    await testRecursiveInjection('$dir/$line');
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

// ruleid: command-injection-process-run
extension UnsafeProcess on String {
  // ruleid: command-injection-process-run
  Future<ProcessResult> execute() async => Process.run(this, []);
}

// ok: command-injection-process-run
extension SafeProcess on String {
  // ok: command-injection-process-run
  Future<ProcessResult> execute() async {
    // ok: command-injection-process-run
    const allowed = ['ls', 'date', 'pwd'];
    // ok: command-injection-process-run
    if (!allowed.contains(this)) throw ArgumentError('Command not allowed');
    return await Process.run(this, []);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Конструкторы и фабрики
// =============================================================================

// ruleid: command-injection-process-run
class CommandFactory {
  // ruleid: command-injection-process-run
  static Future<ProcessResult> create(String command) async {
    return await Process.run(command, []);
  }
}

// ok: command-injection-process-run
class SafeCommandFactory {
  // ok: command-injection-process-run
  static Future<ProcessResult> create(String command) async {
    // ok: command-injection-process-run
    const allowed = ['ls', 'cat', 'echo'];
    // ok: command-injection-process-run
    if (!allowed.contains(command)) throw ArgumentError('Command not allowed');
    return await Process.run(command, []);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Комментарии и строки (не код)
// =============================================================================

void testStringNotCode() {
  // ok: command-injection-process-run
  final comment = 'Process.run(command, args) is dangerous with user input';

  // ok: command-injection-process-run
  final docString = 'Use Process.run(\'ls\', [\'-la\']) for safe execution';

  // ok: command-injection-process-run
  final config = {'command': 'ls', 'args': ['-la']};

  // ok: command-injection-process-run
  print('Run: Process.run(command, args)');
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полные сценарии использования
// =============================================================================

// ruleid: command-injection-process-run
class UnsafeFileProcessor {
  // ruleid: command-injection-process-run
  Future<void> processFile(String filePath) async {
    // ruleid: command-injection-process-run
    final content = await Process.run('cat', [filePath]);
    // ruleid: command-injection-process-run
    await Process.run('grep', [searchTerm, filePath]);
    // ruleid: command-injection-process-run
    await Process.run('rm', [filePath]);
  }
}

// ok: command-injection-process-run
class SafeFileProcessor {
  // ok: command-injection-process-run
  Future<void> processFile(String filePath) async {
    // ok: command-injection-process-run
    if (!filePath.endsWith('.txt')) return;
    // ok: command-injection-process-run
    final content = await File(filePath).readAsString();
    // ok: command-injection-process-run
    await File('processed_${filePath}').writeAsString(content);
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации написания
// =============================================================================

Future<void> testDetectionVariations(String userInput) async {
  // ruleid: command-injection-process-run
  final v1 = await Process.run('ls', [userInput]);

  // ruleid: command-injection-process-run
  final v2 = await Process.run('ls', ['$userInput']);

  // ruleid: command-injection-process-run
  final v3 = await Process.run('ls', ['-la ' + userInput]);

  // ruleid: command-injection-process-run
  final v4 = await Process.run('ls $userInput', [], runInShell: true);

  // ok: command-injection-process-run
  final safe1 = await Process.run('ls', ['-la']);

  // ok: command-injection-process-run
  final safe2 = await Process.run('ls', [trustedPath]);
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testContextAnalysis() {
  // ok: command-injection-process-run
  final comment = 'Process.run(command, args) with user input is dangerous';

  // ok: command-injection-process-run
  final docString = 'Use Process.run(\'ls\', [\'-la\']) for safe execution';

  // ok: command-injection-process-run
  final logMessage = print('Executing: Process.run($command, $args)');
}

// ruleid: command-injection-process-run
Future<void> testActualVulnerableCode(String userInput) async {
  // ruleid: command-injection-process-run
  final result = await Process.run('ls', [userInput]);
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

void _processData(String data) {}

// Глобальные переменные для тестов
String userInput = 'test';
String filePath = '/tmp/file.txt';
String userPath = '/tmp/user';
String command = 'ls';
String arg1 = '-la';
String arg2 = '/tmp';
String searchTerm = 'test';
String fileName = 'file.txt';
String message = 'hello';
String directory = '/tmp';
String file = 'test.txt';
String url = 'https://example.com';
String userScript = 'echo test';
String dir = '/tmp';
String pattern = 'test';
String envVar = 'test';
String userName = 'test';
List<String> arguments = ['-la'];
List<String> files = ['file1.txt', 'file2.txt'];
List<String> commands = ['ls', 'date'];
bool useSudo = false;
bool condition = false;
String trustedPath = '/usr/local/bin/app';