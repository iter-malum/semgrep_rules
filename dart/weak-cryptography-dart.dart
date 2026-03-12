// test_weak_cryptography.dart
// Тест для правила: weak-cryptography-dart
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/pointycastle.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: weak-cryptography-dart
const String SAFE_ALGORITHM = 'AES-256-GCM';

// ok: weak-cryptography-dart
const String SAFE_HASH = 'SHA-256';

// ok: weak-cryptography-dart
const int SAFE_KEY_SIZE = 256;

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: ECB режим шифрования (небезопасно)
// =============================================================================

// ruleid: weak-cryptography-dart
final ecbEncrypter1 = Encrypter(AES(key, mode: AESMode.ecb));

// ruleid: weak-cryptography-dart
final ecbEncrypter2 = Encrypter(AES(key, mode: AESMode.ecb));

// ruleid: weak-cryptography-dart
final ecbEncrypter3 = AESBlockCipher(mode: AESMode.ecb);

Future<void> testECBEncryption() async {
  // ruleid: weak-cryptography-dart
  final encrypter1 = Encrypter(AES(key, mode: AESMode.ecb));

  // ruleid: weak-cryptography-dart
  final encrypter2 = Encrypter(AES(key, mode: AESMode.ecb));

  // ruleid: weak-cryptography-dart
  final cipher = AESBlockCipher(mode: AESMode.ecb);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: MD5 хеширование (слабый алгоритм)
// =============================================================================

// ruleid: weak-cryptography-dart
final md5Hash1 = md5.convert(utf8.encode('data'));

// ruleid: weak-cryptography-dart
final md5Hash2 = md5.convert(bytes);

// ruleid: weak-cryptography-dart
final md5Hash3 = MD5Digest().process(inputBytes);

Future<void> testMD5Hashing(String data, Uint8List bytes) async {
  // ruleid: weak-cryptography-dart
  final hash1 = md5.convert(utf8.encode(data));

  // ruleid: weak-cryptography-dart
  final hash2 = md5.convert(bytes);

  // ruleid: weak-cryptography-dart
  final hash3 = MD5Digest().process(inputBytes);

  // ruleid: weak-cryptography-dart
  final hash4 = Digest('MD5').convert(bytes);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: SHA1 хеширование (слабый алгоритм)
// =============================================================================

// ruleid: weak-cryptography-dart
final sha1Hash1 = sha1.convert(utf8.encode('data'));

// ruleid: weak-cryptography-dart
final sha1Hash2 = sha1.convert(bytes);

// ruleid: weak-cryptography-dart
final sha1Hash3 = SHA1Digest().process(inputBytes);

Future<void> testSHA1Hashing(String data, Uint8List bytes) async {
  // ruleid: weak-cryptography-dart
  final hash1 = sha1.convert(utf8.encode(data));

  // ruleid: weak-cryptography-dart
  final hash2 = sha1.convert(bytes);

  // ruleid: weak-cryptography-dart
  final hash3 = SHA1Digest().process(inputBytes);

  // ruleid: weak-cryptography-dart
  final hash4 = Digest('SHA-1').convert(bytes);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Слабые ключи шифрования
// =============================================================================

// ruleid: weak-cryptography-dart
final weakKey1 = Key.fromUtf8('12345678'); // 64 бита - слишком слабо

// ruleid: weak-cryptography-dart
final weakKey2 = Key.fromUtf8('short'); // Менее 128 бит

// ruleid: weak-cryptography-dart
final weakKey3 = Key(Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8])); // 64 бита

Future<void> testWeakKeys() async {
  // ruleid: weak-cryptography-dart
  final key1 = Key.fromUtf8('weak1234');

  // ruleid: weak-cryptography-dart
  final key2 = Key.fromUtf8('short');

  // ruleid: weak-cryptography-dart
  final key3 = Key(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]));

  // ruleid: weak-cryptography-dart
  final key4 = Key.fromUtf8('password'); // Предсказуемый ключ
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Слабые режимы шифрования (CBC без аутентификации)
// =============================================================================

// ruleid: weak-cryptography-dart
final cbcEncrypter1 = Encrypter(AES(key, mode: AESMode.cbc));

// ruleid: weak-cryptography-dart
final cbcEncrypter2 = Encrypter(AES(key, mode: AESMode.cbc));

Future<void> testCBCWithoutAuth() async {
  // ruleid: weak-cryptography-dart
  final encrypter1 = Encrypter(AES(key, mode: AESMode.cbc));

  // ruleid: weak-cryptography-dart
  final encrypter2 = Encrypter(AES(key, mode: AESMode.cbc));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: DES/3DES шифрование (устаревшее)
// =============================================================================

// ruleid: weak-cryptography-dart
final desCipher1 = DESBlockCipher();

// ruleid: weak-cryptography-dart
final desCipher2 = DESEngine();

// ruleid: weak-cryptography-dart
final tripleDesCipher = TripleDesEngine();

Future<void> testDesEncryption() async {
  // ruleid: weak-cryptography-dart
  final cipher1 = DESBlockCipher();

  // ruleid: weak-cryptography-dart
  final cipher2 = DESEngine();

  // ruleid: weak-cryptography-dart
  final cipher3 = TripleDesEngine();
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: RC4 шифрование (слабый потоковый шифр)
// =============================================================================

// ruleid: weak-cryptography-dart
final rc4Cipher1 = RC4Engine();

// ruleid: weak-cryptography-dart
final rc4Cipher2 = RC4Engine(keyParam);

Future<void> testRC4Encryption() async {
  // ruleid: weak-cryptography-dart
  final cipher1 = RC4Engine();

  // ruleid: weak-cryptography-dart
  final cipher2 = RC4Engine(keyParam);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Статические IV/Nonce (критично!)
// =============================================================================

// ruleid: weak-cryptography-dart
final staticIv1 = IV.fromUtf8('0000000000000000');

// ruleid: weak-cryptography-dart
final staticIv2 = IV(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

// ruleid: weak-cryptography-dart
final staticNonce = IV.fromUtf8('1234567890123456');

Future<void> testStaticIV() async {
  // ruleid: weak-cryptography-dart
  final iv1 = IV.fromUtf8('0000000000000000');

  // ruleid: weak-cryptography-dart
  final iv2 = IV(Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));

  // ruleid: weak-cryptography-dart
  final iv3 = IV.fromUtf8('static_iv_value!');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Комбинированные уязвимости
// =============================================================================

// ruleid: weak-cryptography-dart
final combinedWeak1 = Encrypter(AES(key, mode: AESMode.ecb));
// ruleid: weak-cryptography-dart
final combinedHash1 = md5.convert(data);

Future<void> testCombinedWeakness(String data) async {
  // ruleid: weak-cryptography-dart
  final encrypter = Encrypter(AES(key, mode: AESMode.ecb));

  // ruleid: weak-cryptography-dart
  final hash = md5.convert(utf8.encode(data));

  // ruleid: weak-cryptography-dart
  final iv = IV.fromUtf8('0000000000000000');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Классы и методы со слабой криптографией
// =============================================================================

class WeakCryptoService {
  // ruleid: weak-cryptography-dart
  String hashPassword(String password) {
    return md5.convert(utf8.encode(password)).toString();
  }

  // ruleid: weak-cryptography-dart
  String hashData(String data) {
    return sha1.convert(utf8.encode(data)).toString();
  }

  // ruleid: weak-cryptography-dart
  Encrypted encryptECB(String data) {
    final encrypter = Encrypter(AES(key, mode: AESMode.ecb));
    return encrypter.encrypt(data);
  }

  // ruleid: weak-cryptography-dart
  Encrypted encryptWithStaticIV(String data) {
    final iv = IV.fromUtf8('0000000000000000');
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
    return encrypter.encrypt(data, iv: iv);
  }
}

// ruleid: weak-cryptography-dart
class InsecureTokenGenerator {
  // ruleid: weak-cryptography-dart
  String generateToken(String input) {
    return sha1.convert(utf8.encode(input)).toString();
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Хеш-функции для паролей (небезопасно)
// =============================================================================

// ruleid: weak-cryptography-dart
final passwordHash1 = md5.convert(utf8.encode(password));

// ruleid: weak-cryptography-dart
final passwordHash2 = sha1.convert(utf8.encode(password));

Future<void> testInsecurePasswordHashing(String password) async {
  // ruleid: weak-cryptography-dart
  final hash1 = md5.convert(utf8.encode(password)).toString();

  // ruleid: weak-cryptography-dart
  final hash2 = sha1.convert(utf8.encode(password)).toString();

  // ruleid: weak-cryptography-dart
  final hash3 = SHA1Digest().process(utf8.encode(password));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамический выбор алгоритма (может быть опасным)
// =============================================================================

// ruleid: weak-cryptography-dart
final dynamicHash1 = getHashFunction(algorithmName).convert(data);

// ruleid: weak-cryptography-dart
final dynamicEncrypter1 = getEncrypter(mode);

Future<void> testDynamicAlgorithm(String algorithmName, String mode) async {
  // ruleid: weak-cryptography-dart
  final hash = getHashFunction(algorithmName).convert(data);

  // ruleid: weak-cryptography-dart
  final encrypter = getEncrypter(mode);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные алгоритмы хеширования
// =============================================================================

// ok: weak-cryptography-dart
final safeHash1 = sha256.convert(utf8.encode('data'));

// ok: weak-cryptography-dart
final safeHash2 = sha512.convert(utf8.encode('data'));

// ok: weak-cryptography-dart
final safeHash3 = SHA256Digest().process(inputBytes);

// ok: weak-cryptography-dart
final safeHash4 = SHA512Digest().process(inputBytes);

Future<void> testSafeHashing(String data, Uint8List bytes) async {
  // ok: weak-cryptography-dart
  final hash1 = sha256.convert(utf8.encode(data));

  // ok: weak-cryptography-dart
  final hash2 = sha512.convert(utf8.encode(data));

  // ok: weak-cryptography-dart
  final hash3 = SHA256Digest().process(bytes);

  // ok: weak-cryptography-dart
  final hash4 = SHA512Digest().process(bytes);

  // ok: weak-cryptography-dart
  final hash5 = Digest('SHA-256').convert(bytes);

  // ok: weak-cryptography-dart
  final hash6 = Digest('SHA-512').convert(bytes);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные режимы шифрования
// =============================================================================

// ok: weak-cryptography-dart
final safeEncrypter1 = Encrypter(AES(key, mode: AESMode.gcm));

// ok: weak-cryptography-dart
final safeEncrypter2 = Encrypter(AES(key, mode: AESMode.cbc));

// ok: weak-cryptography-dart
final safeEncrypter3 = Encrypter(AES(key, mode: AESMode.ctr));

Future<void> testSafeEncryption() async {
  // ok: weak-cryptography-dart
  final encrypter1 = Encrypter(AES(key, mode: AESMode.gcm));

  // ok: weak-cryptography-dart
  final encrypter2 = Encrypter(AES(key, mode: AESMode.cbc));

  // ok: weak-cryptography-dart
  final encrypter3 = Encrypter(AES(key, mode: AESMode.ctr));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные ключи (достаточная длина)
// =============================================================================

// ok: weak-cryptography-dart
final safeKey1 = Key.fromUtf8('0123456789abcdef0123456789abcdef'); // 256 бит

// ok: weak-cryptography-dart
final safeKey2 = Key(Uint8List.fromList(List.generate(32, (i) => i))); // 256 бит

// ok: weak-cryptography-dart
final safeKey3 = Key.fromSecureRandom(32); // 256 бит из CSPRNG

Future<void> testSafeKeys() async {
  // ok: weak-cryptography-dart
  final key1 = Key.fromUtf8('0123456789abcdef0123456789abcdef');

  // ok: weak-cryptography-dart
  final key2 = Key(Uint8List.fromList(List.generate(32, (i) => i)));

  // ok: weak-cryptography-dart
  final key3 = Key.fromSecureRandom(32);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные IV/Nonce (случайные)
// =============================================================================

// ok: weak-cryptography-dart
final safeIv1 = IV.fromSecureRandom(16);

// ok: weak-cryptography-dart
final safeIv2 = IV(Uint8List.fromList(List.generate(16, (i) => random.nextInt(256))));

Future<void> testSafeIV() async {
  // ok: weak-cryptography-dart
  final iv1 = IV.fromSecureRandom(16);

  // ok: weak-cryptography-dart
  final iv2 = IV(Uint8List.fromList(List.generate(16, (i) => random.nextInt(256))));
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные функции для паролей
// =============================================================================

// ok: weak-cryptography-dart
final safePasswordHash1 = PBKDF2KeyDerivator(SHA256Digest());

// ok: weak-cryptography-dart
final safePasswordHash2 = Scrypt();

// ok: weak-cryptography-dart
final safePasswordHash3 = Argon2();

Future<void> testSafePasswordHashing(String password) async {
  // ok: weak-cryptography-dart
  final pbkdf2 = PBKDF2KeyDerivator(SHA256Digest());

  // ok: weak-cryptography-dart
  final scrypt = Scrypt();

  // ok: weak-cryptography-dart
  final argon2 = Argon2();

  // ok: weak-cryptography-dart
  final bcryptHash = await BCrypt.hashpw(password, await BCrypt.gensalt());
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: CBC с HMAC (аутентифицированное шифрование)
// =============================================================================

// ok: weak-cryptography-dart
final safeCbcWithHmac = Encrypter(AES(key, mode: AESMode.cbc))
  ..encrypt(data, iv: iv, additionalData: hmac);

Future<void> testSafeCBCWithAuth() async {
  // ok: weak-cryptography-dart
  final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
  // ok: weak-cryptography-dart
  final encrypted = encrypter.encrypt(data, iv: iv, additionalData: hmac);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частично безопасные конфигурации
// =============================================================================

// ruleid: weak-cryptography-dart
final partialSafe1 = Encrypter(AES(key, mode: AESMode.gcm));
// ok: weak-cryptography-dart (GCM безопасен)
// Но если IV статический - всё равно уязвимо
// ruleid: weak-cryptography-dart
final partialSafe2 = IV.fromUtf8('0000000000000000');

// ruleid: weak-cryptography-dart
final partialSafe3 = Encrypter(AES(weakKey, mode: AESMode.gcm)); // Слабый ключ

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условное использование алгоритмов
// =============================================================================

// ruleid: weak-cryptography-dart
final conditionalAlgo1 = useWeak ? md5 : sha256;

// ruleid: weak-cryptography-dart
final conditionalMode1 = useECB ? AESMode.ecb : AESMode.gcm;

Future<void> testConditionalAlgorithms(bool useWeak, bool useECB) async {
  // ruleid: weak-cryptography-dart
  final hash = useWeak ? md5 : sha256;

  // ruleid: weak-cryptography-dart
  final mode = useECB ? AESMode.ecb : AESMode.gcm;
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Устаревшие но ещё используемые алгоритмы
// =============================================================================

// ruleid: weak-cryptography-dart
final ripemd160Hash = RIPEMD160Digest().process(data);

// ruleid: weak-cryptography-dart
final whirlpoolHash = WhirlpoolDigest().process(data);

Future<void> testLegacyAlgorithms() async {
  // ruleid: weak-cryptography-dart
  final hash1 = RIPEMD160Digest().process(data);

  // ruleid: weak-cryptography-dart
  final hash2 = WhirlpoolDigest().process(data);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Кастомные реализации криптографии
// =============================================================================

// ruleid: weak-cryptography-dart
class CustomCrypto {
  // ruleid: weak-cryptography-dart
  String hash(String input) => md5.convert(utf8.encode(input)).toString();

  // ruleid: weak-cryptography-dart
  Encrypted encrypt(String data) => Encrypter(AES(key, mode: AESMode.ecb)).encrypt(data);
}

// ok: weak-cryptography-dart
class SafeCustomCrypto {
  // ok: weak-cryptography-dart
  String hash(String input) => sha256.convert(utf8.encode(input)).toString();

  // ok: weak-cryptography-dart
  Encrypted encrypt(String data) => Encrypter(AES(key, mode: AESMode.gcm)).encrypt(data);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Миграция со слабых алгоритмов
// =============================================================================

// ruleid: weak-cryptography-dart
Future<String> migrateHash(String password, bool isLegacy) async {
  // ruleid: weak-cryptography-dart
  if (isLegacy) return md5.convert(utf8.encode(password)).toString();
  // ok: weak-cryptography-dart
  return sha256.convert(utf8.encode(password)).toString();
}

// ok: weak-cryptography-dart
Future<String> safeMigration(String password, bool isLegacy) async {
  // ok: weak-cryptography-dart
  if (isLegacy) {
    // Миграция: пересчитываем хеш на безопасный алгоритм
    return sha256.convert(utf8.encode(password)).toString();
  }
  return sha256.convert(utf8.encode(password)).toString();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

// ruleid: weak-cryptography-dart
extension WeakHash on String {
  // ruleid: weak-cryptography-dart
  String md5Hash() => md5.convert(utf8.encode(this)).toString();

  // ruleid: weak-cryptography-dart
  String sha1Hash() => sha1.convert(utf8.encode(this)).toString();
}

// ok: weak-cryptography-dart
extension SafeHash on String {
  // ok: weak-cryptography-dart
  String sha256Hash() => sha256.convert(utf8.encode(this)).toString();

  // ok: weak-cryptography-dart
  String sha512Hash() => sha512.convert(utf8.encode(this)).toString();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Фабрики и конструкторы
// =============================================================================

// ruleid: weak-cryptography-dart
class CryptoFactory {
  // ruleid: weak-cryptography-dart
  static Hash getHash(String algorithm) {
    if (algorithm == 'md5') return md5;
    if (algorithm == 'sha1') return sha1;
    return sha256;
  }
}

// ok: weak-cryptography-dart
class SafeCryptoFactory {
  // ok: weak-cryptography-dart
  static Hash getHash(String algorithm) {
    // ok: weak-cryptography-dart
    const allowed = ['sha256', 'sha512'];
    // ok: weak-cryptography-dart
    if (!allowed.contains(algorithm)) throw ArgumentError('Algorithm not allowed');
    return algorithm == 'sha256' ? sha256 : sha512;
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Асинхронные паттерны
// =============================================================================

// ruleid: weak-cryptography-dart
Stream<String> testStreamHash(List<String> inputs) async* {
  for (var input in inputs) {
    // ruleid: weak-cryptography-dart
    yield md5.convert(utf8.encode(input)).toString();
  }
}

// ok: weak-cryptography-dart
Stream<String> testSafeStream(List<String> inputs) async* {
  for (var input in inputs) {
    // ok: weak-cryptography-dart
    yield sha256.convert(utf8.encode(input)).toString();
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Комментарии и строки (не код)
// =============================================================================

void testStringNotCode() {
  // ok: weak-cryptography-dart
  final comment = 'Use md5.convert() for hashing (deprecated - use sha256 instead)';

  // ok: weak-cryptography-dart
  final docString = 'AESMode.ecb is insecure, use AESMode.gcm';

  // ok: weak-cryptography-dart
  final config = {'algorithm': 'md5', 'mode': 'ecb'};

  // ok: weak-cryptography-dart
  print('Warning: SHA1 is deprecated, use SHA-256');
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полные сценарии использования
// =============================================================================

// ruleid: weak-cryptography-dart
class InsecureAuthService {
  // ruleid: weak-cryptography-dart
  String hashPassword(String password) {
    return md5.convert(utf8.encode(password)).toString();
  }

  // ruleid: weak-cryptography-dart
  String generateToken(String userId) {
    return sha1.convert(utf8.encode(userId + timestamp)).toString();
  }

  // ruleid: weak-cryptography-dart
  Encrypted encryptData(String data) {
    final encrypter = Encrypter(AES(key, mode: AESMode.ecb));
    return encrypter.encrypt(data);
  }

  // ruleid: weak-cryptography-dart
  IV getIV() {
    return IV.fromUtf8('0000000000000000');
  }
}

// ok: weak-cryptography-dart
class SecureAuthService {
  // ok: weak-cryptography-dart
  Future<String> hashPassword(String password) async {
    final salt = await generateSalt();
    // ok: weak-cryptography-dart
    final pbkdf2 = PBKDF2KeyDerivator(SHA256Digest());
    return pbkdf2.process(utf8.encode(password + salt)).toString();
  }

  // ok: weak-cryptography-dart
  String generateToken(String userId) {
    // ok: weak-cryptography-dart
    return sha256.convert(utf8.encode(userId + timestamp + secret)).toString();
  }

  // ok: weak-cryptography-dart
  Encrypted encryptData(String data) {
    // ok: weak-cryptography-dart
    final encrypter = Encrypter(AES(key, mode: AESMode.gcm));
    // ok: weak-cryptography-dart
    final iv = IV.fromSecureRandom(16);
    return encrypter.encrypt(data, iv: iv);
  }
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации написания
// =============================================================================

Future<void> testDetectionVariations(String data) async {
  // ruleid: weak-cryptography-dart
  final v1 = md5.convert(utf8.encode(data));

  // ruleid: weak-cryptography-dart
  final v2 = sha1.convert(utf8.encode(data));

  // ruleid: weak-cryptography-dart
  final v3 = Encrypter(AES(key, mode: AESMode.ecb));

  // ruleid: weak-cryptography-dart
  final v4 = MD5Digest().process(bytes);

  // ruleid: weak-cryptography-dart
  final v5 = SHA1Digest().process(bytes);

  // ok: weak-cryptography-dart
  final safe1 = sha256.convert(utf8.encode(data));

  // ok: weak-cryptography-dart
  final safe2 = sha512.convert(utf8.encode(data));

  // ok: weak-cryptography-dart
  final safe3 = Encrypter(AES(key, mode: AESMode.gcm));

  // ok: weak-cryptography-dart
  final safe4 = SHA256Digest().process(bytes);

  // ok: weak-cryptography-dart
  final safe5 = SHA512Digest().process(bytes);
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testContextAnalysis() {
  // ok: weak-cryptography-dart
  final comment = 'md5.convert() is deprecated, use sha256 instead';

  // ok: weak-cryptography-dart
  final docString = 'AESMode.ecb is insecure for most use cases';

  // ok: weak-cryptography-dart
  final logMessage = print('Warning: SHA1 is cryptographically broken');

  // ok: weak-cryptography-dart
  final config = {'hash': 'md5', 'encryption': 'aes-ecb'};
}

// ruleid: weak-cryptography-dart
Future<void> testActualVulnerableCode(String data) async {
  // ruleid: weak-cryptography-dart
  final hash = md5.convert(utf8.encode(data));
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

Hash getHashFunction(String name) {
  if (name == 'md5') return md5;
  if (name == 'sha1') return sha1;
  return sha256;
}

Encrypter getEncrypter(String mode) {
  if (mode == 'ecb') return Encrypter(AES(key, mode: AESMode.ecb));
  return Encrypter(AES(key, mode: AESMode.gcm));
}

Uint8List generateSalt() => Uint8List.fromList(List.generate(16, (_) => random.nextInt(256)));

// Глобальные переменные для тестов
Key key = Key.fromUtf8('0123456789abcdef0123456789abcdef');
IV iv = IV.fromSecureRandom(16);
Uint8List data = Uint8List.fromList([1, 2, 3]);
Uint8List bytes = Uint8List.fromList([4, 5, 6]);
Uint8List inputBytes = Uint8List.fromList([7, 8, 9]);
String password = 'secret123';
String timestamp = DateTime.now().toString();
String secret = 'my-secret-key';
KeyParam keyParam = KeyParameter(key.bytes);
bool useWeak = true;
bool useECB = true;
String algorithmName = 'md5';
dynamic hmac = null;
var random = Random.secure();