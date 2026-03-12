// test_sql_injection.dart
// Тест для правила: sql-injection-sqflite
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'package:sqflite/sqflite.dart';
import 'package:sqflite_common_ffi/sqflite_common_ffi.dart';

// =============================================================================
// ГЛОБАЛЬНЫЕ КОНСТАНТЫ
// =============================================================================

// ok: sql-injection-sqflite
const String TABLE_USERS = 'users';

// ok: sql-injection-sqflite
const String COLUMN_ID = 'id';

// ok: sql-injection-sqflite
const String SAFE_QUERY = 'SELECT * FROM users WHERE id = ?';

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Интерполяция строк в rawQuery
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableQuery1 = await database.rawQuery('SELECT * FROM users WHERE id = $userId');

// ruleid: sql-injection-sqflite
final vulnerableQuery2 = await database.rawQuery('SELECT * FROM users WHERE email = \'$email\'');

// ruleid: sql-injection-sqflite
final vulnerableQuery3 = await database.rawQuery('SELECT * FROM users WHERE name = "$name"');

Future<void> testRawQueryInjection(String userId, String email) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE id = $userId');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE email = \'$email\' AND active = 1');

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE created_at > \'$date\'');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Конкатенация строк в запросах
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableConcat1 = await database.rawQuery('SELECT * FROM users WHERE id = ' + userId);

// ruleid: sql-injection-sqflite
final vulnerableConcat2 = await database.rawQuery('SELECT * FROM users WHERE name = \'' + name + '\'');

Future<void> testConcatInjection(String userId, String name) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE id = ' + userId);

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE name = \'' + name + '\'');

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM ' + tableName + ' WHERE id = ' + id);
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: rawInsert с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableInsert1 = await database.rawInsert('INSERT INTO users (name, email) VALUES (\'$name\', \'$email\')');

// ruleid: sql-injection-sqflite
final vulnerableInsert2 = await database.rawInsert('INSERT INTO users (name) VALUES (\'$userName\')');

Future<void> testRawInsertInjection(String name, String email, String userName) async {
  // ruleid: sql-injection-sqflite
  final id1 = await database.rawInsert('INSERT INTO users (name, email) VALUES (\'$name\', \'$email\')');

  // ruleid: sql-injection-sqflite
  final id2 = await database.rawInsert('INSERT INTO users (name) VALUES (\'$userName\')');

  // ruleid: sql-injection-sqflite
  final id3 = await database.rawInsert('INSERT INTO $tableName (name) VALUES (\'$name\')');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: rawUpdate с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableUpdate1 = await database.rawUpdate('UPDATE users SET name = \'$name\' WHERE id = $id');

// ruleid: sql-injection-sqflite
final vulnerableUpdate2 = await database.rawUpdate('UPDATE users SET email = \'$email\' WHERE id = $userId');

Future<void> testRawUpdateInjection(String name, String email, String userId, int id) async {
  // ruleid: sql-injection-sqflite
  final count1 = await database.rawUpdate('UPDATE users SET name = \'$name\' WHERE id = $id');

  // ruleid: sql-injection-sqflite
  final count2 = await database.rawUpdate('UPDATE users SET email = \'$email\' WHERE id = $userId');

  // ruleid: sql-injection-sqflite
  final count3 = await database.rawUpdate('UPDATE $tableName SET status = \'$status\' WHERE id = $id');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: rawDelete с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableDelete1 = await database.rawDelete('DELETE FROM users WHERE id = $userId');

// ruleid: sql-injection-sqflite
final vulnerableDelete2 = await database.rawDelete('DELETE FROM users WHERE email = \'$email\'');

Future<void> testRawDeleteInjection(String userId, String email) async {
  // ruleid: sql-injection-sqflite
  final count1 = await database.rawDelete('DELETE FROM users WHERE id = $userId');

  // ruleid: sql-injection-sqflite
  final count2 = await database.rawDelete('DELETE FROM users WHERE email = \'$email\'');

  // ruleid: sql-injection-sqflite
  final count3 = await database.rawDelete('DELETE FROM $tableName WHERE id = $id');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: execute с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableExecute1 = await database.execute('CREATE TABLE $tableName (id INTEGER, name TEXT)');

// ruleid: sql-injection-sqflite
final vulnerableExecute2 = await database.execute('DROP TABLE IF EXISTS $tableName');

Future<void> testExecuteInjection(String tableName) async {
  // ruleid: sql-injection-sqflite
  await database.execute('CREATE TABLE $tableName (id INTEGER, name TEXT)');

  // ruleid: sql-injection-sqflite
  await database.execute('DROP TABLE IF EXISTS $tableName');

  // ruleid: sql-injection-sqflite
  await database.execute('ALTER TABLE users ADD COLUMN $columnName TEXT');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Сложные запросы с множественной интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableComplex1 = await database.rawQuery('SELECT * FROM users WHERE name = \'$name\' AND email = \'$email\' AND age > $age');

// ruleid: sql-injection-sqflite
final vulnerableComplex2 = await database.rawQuery('SELECT * FROM $tableName WHERE $columnName = \'$value\' ORDER BY $orderBy');

Future<void> testComplexInjection(String name, String email, int age, String tableName, String columnName, String value, String orderBy) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE name = \'$name\' AND email = \'$email\' AND age > $age');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM $tableName WHERE $columnName = \'$value\' ORDER BY $orderBy');

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT $columns FROM $table WHERE $where');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Динамическое построение запросов
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableDynamic1 = await database.rawQuery('SELECT * FROM users WHERE ' + whereClause);

// ruleid: sql-injection-sqflite
final vulnerableDynamic2 = await database.rawQuery(query);

Future<void> testDynamicInjection(String whereClause, String query) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE ' + whereClause);

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery(query);

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery(buildQuery(userInput));
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: LIKE запросы с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableLike1 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'%$searchTerm%\'');

// ruleid: sql-injection-sqflite
final vulnerableLike2 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'$searchTerm%\'');

// ruleid: sql-injection-sqflite
final vulnerableLike3 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'%$searchTerm\'');

Future<void> testLikeInjection(String searchTerm) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'%$searchTerm%\'');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'$searchTerm%\'');

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE name LIKE \'%$searchTerm\'');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: IN запросы с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableIn1 = await database.rawQuery('SELECT * FROM users WHERE id IN ($ids)');

// ruleid: sql-injection-sqflite
final vulnerableIn2 = await database.rawQuery('SELECT * FROM users WHERE id IN (\'$idList\')');

Future<void> testInInjection(String ids, String idList) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE id IN ($ids)');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE id IN (\'$idList\')');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: ORDER BY и GROUP BY с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableOrderBy1 = await database.rawQuery('SELECT * FROM users ORDER BY $columnName');

// ruleid: sql-injection-sqflite
final vulnerableGroupBy1 = await database.rawQuery('SELECT COUNT(*) FROM users GROUP BY $columnName');

Future<void> testOrderByInjection(String columnName) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users ORDER BY $columnName');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT COUNT(*) FROM users GROUP BY $columnName');

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users ORDER BY $column $direction');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: JOIN запросы с интерполяцией
// =============================================================================

// ruleid: sql-injection-sqflite
final vulnerableJoin1 = await database.rawQuery('SELECT * FROM users JOIN $tableName ON users.id = $tableName.user_id');

// ruleid: sql-injection-sqflite
final vulnerableJoin2 = await database.rawQuery('SELECT * FROM users JOIN orders ON users.id = orders.user_id WHERE orders.status = \'$status\'');

Future<void> testJoinInjection(String tableName, String status) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users JOIN $tableName ON users.id = $tableName.user_id');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users JOIN orders ON users.id = orders.user_id WHERE orders.status = \'$status\'');
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Классы и методы с уязвимостями
// =============================================================================

class UserRepository {
  final Database database;

  UserRepository(this.database);

  // ruleid: sql-injection-sqflite
  Future<List<Map>> getUserById(String id) async {
    return await database.rawQuery('SELECT * FROM users WHERE id = $id');
  }

  // ruleid: sql-injection-sqflite
  Future<List<Map>> getUserByEmail(String email) async {
    return await database.rawQuery('SELECT * FROM users WHERE email = \'$email\'');
  }

  // ruleid: sql-injection-sqflite
  Future<int> updateUser(String id, String name) async {
    return await database.rawUpdate('UPDATE users SET name = \'$name\' WHERE id = $id');
  }

  // ruleid: sql-injection-sqflite
  Future<int> deleteUser(String id) async {
    return await database.rawDelete('DELETE FROM users WHERE id = $id');
  }

  // ruleid: sql-injection-sqflite
  Future<int> createUser(String name, String email) async {
    return await database.rawInsert('INSERT INTO users (name, email) VALUES (\'$name\', \'$email\')');
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные параметризированные запросы
// =============================================================================

// ok: sql-injection-sqflite
final safeQuery1 = await database.rawQuery('SELECT * FROM users WHERE id = ?', [userId]);

// ok: sql-injection-sqflite
final safeQuery2 = await database.rawQuery('SELECT * FROM users WHERE email = ?', [email]);

// ok: sql-injection-sqflite
final safeQuery3 = await database.rawQuery('SELECT * FROM users WHERE id = ? AND email = ?', [userId, email]);

Future<void> testSafeRawQuery(String userId, String email, int age) async {
  // ok: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE id = ?', [userId]);

  // ok: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE email = ?', [email]);

  // ok: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE id = ? AND email = ? AND age > ?', [userId, email, age]);

  // ok: sql-injection-sqflite
  final result4 = await database.rawQuery('SELECT * FROM users WHERE id IN (?, ?, ?)', [id1, id2, id3]);
}

// ok: sql-injection-sqflite
final safeInsert1 = await database.rawInsert('INSERT INTO users (name, email) VALUES (?, ?)', [name, email]);

// ok: sql-injection-sqflite
final safeInsert2 = await database.rawInsert('INSERT INTO users (name) VALUES (?)', [userName]);

Future<void> testSafeRawInsert(String name, String email, String userName) async {
  // ok: sql-injection-sqflite
  final id1 = await database.rawInsert('INSERT INTO users (name, email) VALUES (?, ?)', [name, email]);

  // ok: sql-injection-sqflite
  final id2 = await database.rawInsert('INSERT INTO users (name) VALUES (?)', [userName]);
}

// ok: sql-injection-sqflite
final safeUpdate1 = await database.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [name, id]);

// ok: sql-injection-sqflite
final safeUpdate2 = await database.rawUpdate('UPDATE users SET email = ? WHERE id = ?', [email, userId]);

Future<void> testSafeRawUpdate(String name, String email, String userId, int id) async {
  // ok: sql-injection-sqflite
  final count1 = await database.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [name, id]);

  // ok: sql-injection-sqflite
  final count2 = await database.rawUpdate('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
}

// ok: sql-injection-sqflite
final safeDelete1 = await database.rawDelete('DELETE FROM users WHERE id = ?', [userId]);

// ok: sql-injection-sqflite
final safeDelete2 = await database.rawDelete('DELETE FROM users WHERE email = ?', [email]);

Future<void> testSafeRawDelete(String userId, String email) async {
  // ok: sql-injection-sqflite
  final count1 = await database.rawDelete('DELETE FROM users WHERE id = ?', [userId]);

  // ok: sql-injection-sqflite
  final count2 = await database.rawDelete('DELETE FROM users WHERE email = ?', [email]);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Метод query (безопасный по умолчанию)
// =============================================================================

// ok: sql-injection-sqflite
final safeQueryMethod1 = await database.query('users', where: 'id = ?', whereArgs: [userId]);

// ok: sql-injection-sqflite
final safeQueryMethod2 = await database.query('users', where: 'email = ? AND active = ?', whereArgs: [email, 1]);

// ok: sql-injection-sqflite
final safeQueryMethod3 = await database.query('users', columns: ['id', 'name'], where: 'id = ?', whereArgs: [userId]);

Future<void> testSafeQueryMethod(String userId, String email) async {
  // ok: sql-injection-sqflite
  final result1 = await database.query('users', where: 'id = ?', whereArgs: [userId]);

  // ok: sql-injection-sqflite
  final result2 = await database.query('users', where: 'email = ? AND active = ?', whereArgs: [email, 1]);

  // ok: sql-injection-sqflite
  final result3 = await database.query('users', columns: ['id', 'name'], where: 'id = ?', whereArgs: [userId]);

  // ok: sql-injection-sqflite
  final result4 = await database.query('users', orderBy: 'created_at DESC', limit: 10);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: LIKE запросы с параметризацией
// =============================================================================

// ok: sql-injection-sqflite
final safeLike1 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['%$searchTerm%']);

// ok: sql-injection-sqflite
final safeLike2 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['$searchTerm%']);

// ok: sql-injection-sqflite
final safeLike3 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['%$searchTerm']);

Future<void> testSafeLike(String searchTerm) async {
  // ok: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['%$searchTerm%']);

  // ok: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['$searchTerm%']);

  // ok: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['%$searchTerm']);
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Константные запросы без переменных
// =============================================================================

// ok: sql-injection-sqflite
final constantQuery1 = await database.rawQuery('SELECT * FROM users WHERE id = 1');

// ok: sql-injection-sqflite
final constantQuery2 = await database.rawQuery('SELECT COUNT(*) FROM users');

// ok: sql-injection-sqflite
final constantQuery3 = await database.rawQuery('SELECT * FROM users WHERE active = 1');

Future<void> testConstantQueries() async {
  // ok: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE id = 1');

  // ok: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT COUNT(*) FROM users');

  // ok: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE active = 1');

  // ok: sql-injection-sqflite
  final result4 = await database.rawQuery('SELECT * FROM users ORDER BY created_at DESC');
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные классы и методы
// =============================================================================

class SafeUserRepository {
  final Database database;

  SafeUserRepository(this.database);

  // ok: sql-injection-sqflite
  Future<List<Map>> getUserById(String id) async {
    return await database.rawQuery('SELECT * FROM users WHERE id = ?', [id]);
  }

  // ok: sql-injection-sqflite
  Future<List<Map>> getUserByEmail(String email) async {
    return await database.rawQuery('SELECT * FROM users WHERE email = ?', [email]);
  }

  // ok: sql-injection-sqflite
  Future<int> updateUser(String id, String name) async {
    return await database.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [name, id]);
  }

  // ok: sql-injection-sqflite
  Future<int> deleteUser(String id) async {
    return await database.rawDelete('DELETE FROM users WHERE id = ?', [id]);
  }

  // ok: sql-injection-sqflite
  Future<int> createUser(String name, String email) async {
    return await database.rawInsert('INSERT INTO users (name, email) VALUES (?, ?)', [name, email]);
  }

  // ok: sql-injection-sqflite
  Future<List<Map>> searchUsers(String term) async {
    return await database.rawQuery('SELECT * FROM users WHERE name LIKE ?', ['%$term%']);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная параметризация
// =============================================================================

// ruleid: sql-injection-sqflite
final partialParam1 = await database.rawQuery('SELECT * FROM users WHERE name = \'$name\' AND id = ?', [id]);

// ruleid: sql-injection-sqflite
final partialParam2 = await database.rawQuery('SELECT * FROM $tableName WHERE id = ?', [id]);

Future<void> testPartialParametrization(String name, String tableName, int id) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery('SELECT * FROM users WHERE name = \'$name\' AND id = ?', [id]);

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM $tableName WHERE id = ?', [id]);

  // ruleid: sql-injection-sqflite
  final result3 = await database.rawQuery('SELECT * FROM users WHERE id = ? AND email = \'$email\'', [id]);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Динамические таблицы и колонки
// =============================================================================

// ruleid: sql-injection-sqflite
final dynamicTable1 = await database.rawQuery('SELECT * FROM $tableName WHERE id = ?', [id]);

// ruleid: sql-injection-sqflite
final dynamicColumn1 = await database.rawQuery('SELECT * FROM users ORDER BY $columnName');

// ok: sql-injection-sqflite (белый список таблиц)
Future<void> testSafeDynamicTable(String tableName, int id) async {
  // ok: sql-injection-sqflite
  if (!['users', 'posts', 'comments'].contains(tableName)) return;
  final result = await database.rawQuery('SELECT * FROM $tableName WHERE id = ?', [id]);
}

// ok: sql-injection-sqflite (белый список колонок)
Future<void> testSafeDynamicColumn(String columnName) async {
  // ok: sql-injection-sqflite
  if (!['id', 'name', 'email', 'created_at'].contains(columnName)) return;
  final result = await database.rawQuery('SELECT * FROM users ORDER BY $columnName');
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Условные запросы
// =============================================================================

// ruleid: sql-injection-sqflite
final conditionalQuery1 = await database.rawQuery(condition ? 'SELECT * FROM users WHERE id = $id' : 'SELECT * FROM users');

// ruleid: sql-injection-sqflite
final conditionalQuery2 = await database.rawQuery('SELECT * FROM users WHERE ' + (filter ? 'active = 1' : 'id = $id'));

Future<void> testConditionalQueries(String id, bool condition, bool filter) async {
  // ruleid: sql-injection-sqflite
  final result1 = await database.rawQuery(condition ? 'SELECT * FROM users WHERE id = $id' : 'SELECT * FROM users');

  // ruleid: sql-injection-sqflite
  final result2 = await database.rawQuery('SELECT * FROM users WHERE ' + (filter ? 'active = 1' : 'id = $id'));
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Цепочки запросов
// =============================================================================

// ruleid: sql-injection-sqflite
Future<void> testChainedQueries(String userId) async {
  // ruleid: sql-injection-sqflite
  final user = await database.rawQuery('SELECT * FROM users WHERE id = $userId');
  if (user.isNotEmpty) {
    // ruleid: sql-injection-sqflite
    final orders = await database.rawQuery('SELECT * FROM orders WHERE user_id = $userId');
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Транзакции
// =============================================================================

// ruleid: sql-injection-sqflite
Future<void> testTransactionInjection(String name, String email) async {
  await database.transaction((txn) async {
    // ruleid: sql-injection-sqflite
    await txn.rawInsert('INSERT INTO users (name, email) VALUES (\'$name\', \'$email\')');
    // ruleid: sql-injection-sqflite
    await txn.rawQuery('SELECT * FROM users WHERE email = \'$email\'');
  });
}

// ok: sql-injection-sqflite
Future<void> testSafeTransaction(String name, String email) async {
  await database.transaction((txn) async {
    // ok: sql-injection-sqflite
    await txn.rawInsert('INSERT INTO users (name, email) VALUES (?, ?)', [name, email]);
    // ok: sql-injection-sqflite
    await txn.rawQuery('SELECT * FROM users WHERE email = ?', [email]);
  });
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Batch операции
// =============================================================================

// ruleid: sql-injection-sqflite
Future<void> testBatchInjection(List<String> names) async {
  final batch = database.batch();
  for (var name in names) {
    // ruleid: sql-injection-sqflite
    batch.rawInsert('INSERT INTO users (name) VALUES (\'$name\')');
  }
  await batch.commit();
}

// ok: sql-injection-sqflite
Future<void> testSafeBatch(List<String> names) async {
  final batch = database.batch();
  for (var name in names) {
    // ok: sql-injection-sqflite
    batch.rawInsert('INSERT INTO users (name) VALUES (?)', [name]);
  }
  await batch.commit();
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Вспомогательные функции
// =============================================================================

// ruleid: sql-injection-sqflite
String buildUnsafeQuery(String table, String column, String value) {
  return 'SELECT * FROM $table WHERE $column = \'$value\'';
}

// ok: sql-injection-sqflite
String buildSafeQuery(String table, String column) {
  // Возвращает только структуру запроса, значения передаются отдельно
  return 'SELECT * FROM $table WHERE $column = ?';
}

// ok: sql-injection-sqflite
Future<List<Map>> executeSafeQuery(Database db, String query, List<dynamic> args) async {
  return await db.rawQuery(query, args);
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Миграции и инициализация БД
// =============================================================================

// ok: sql-injection-sqflite (миграции используют константы)
Future<void> testMigration() async {
  // ok: sql-injection-sqflite
  await database.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)');
  // ok: sql-injection-sqflite
  await database.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
}

// ruleid: sql-injection-sqflite
Future<void> testUnsafeMigration(String tableName) async {
  // ruleid: sql-injection-sqflite
  await database.execute('CREATE TABLE IF NOT EXISTS $tableName (id INTEGER PRIMARY KEY)');
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Raw SQL в helper-классах
// =============================================================================

class QueryHelper {
  // ruleid: sql-injection-sqflite
  static Future<List<Map>> find(Database db, String table, String where) async {
    return await db.rawQuery('SELECT * FROM $table WHERE $where');
  }

  // ok: sql-injection-sqflite
  static Future<List<Map>> safeFind(Database db, String table, String where, List<dynamic> args) async {
    return await db.rawQuery('SELECT * FROM $table WHERE $where', args);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Extension методы
// =============================================================================

// ruleid: sql-injection-sqflite
extension UnsafeQuery on Database {
  Future<List<Map>> findById(String table, String id) async {
    return await rawQuery('SELECT * FROM $table WHERE id = $id');
  }
}

// ok: sql-injection-sqflite
extension SafeQuery on Database {
  Future<List<Map>> findById(String table, String id) async {
    return await rawQuery('SELECT * FROM $table WHERE id = ?', [id]);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Комментарии и строки (не код)
// =============================================================================

void testStringNotCode() {
  // ok: sql-injection-sqflite
  final comment = 'SELECT * FROM users WHERE id = $userId'; // Это комментарий!

  // ok: sql-injection-sqflite
  final docString = 'Use rawQuery(\'SELECT * FROM users WHERE id = ?\', [id]) for safety';

  // ok: sql-injection-sqflite
  final config = {'query': 'SELECT * FROM users WHERE id = ?'};
}

// =============================================================================
// КОМПЛЕКСНЫЕ СЦЕНАРИИ: Полные CRUD операции
// =============================================================================

// ruleid: sql-injection-sqflite
class UnsafeCRUD {
  final Database db;
  UnsafeCRUD(this.db);

  // ruleid: sql-injection-sqflite
  Future<List<Map>> read(String id) async => await db.rawQuery('SELECT * FROM users WHERE id = $id');

  // ruleid: sql-injection-sqflite
  Future<int> create(String name, String email) async => await db.rawInsert('INSERT INTO users (name, email) VALUES (\'$name\', \'$email\')');

  // ruleid: sql-injection-sqflite
  Future<int> update(String id, String name) async => await db.rawUpdate('UPDATE users SET name = \'$name\' WHERE id = $id');

  // ruleid: sql-injection-sqflite
  Future<int> delete(String id) async => await db.rawDelete('DELETE FROM users WHERE id = $id');
}

// ok: sql-injection-sqflite
class SafeCRUD {
  final Database db;
  SafeCRUD(this.db);

  // ok: sql-injection-sqflite
  Future<List<Map>> read(String id) async => await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);

  // ok: sql-injection-sqflite
  Future<int> create(String name, String email) async => await db.rawInsert('INSERT INTO users (name, email) VALUES (?, ?)', [name, email]);

  // ok: sql-injection-sqflite
  Future<int> update(String id, String name) async => await db.rawUpdate('UPDATE users SET name = ? WHERE id = ?', [name, id]);

  // ok: sql-injection-sqflite
  Future<int> delete(String id) async => await db.rawDelete('DELETE FROM users WHERE id = ?', [id]);
}

// =============================================================================
// ТЕСТЫ ТОЧНОСТИ ПРАВИЛА: Вариации написания
// =============================================================================

Future<void> testDetectionVariations(String userId, String email) async {
  // ruleid: sql-injection-sqflite
  final v1 = await database.rawQuery('SELECT * FROM users WHERE id = $userId');

  // ruleid: sql-injection-sqflite
  final v2 = await database.rawQuery("SELECT * FROM users WHERE email = '$email'");

  // ruleid: sql-injection-sqflite
  final v3 = await database.rawQuery('SELECT * FROM users WHERE id = ' + userId);

  // ok: sql-injection-sqflite
  final safe1 = await database.rawQuery('SELECT * FROM users WHERE id = ?', [userId]);

  // ok: sql-injection-sqflite
  final safe2 = await database.rawQuery('SELECT * FROM users WHERE email = ?', [email]);
}

// =============================================================================
// КОНТЕКСТНЫЙ АНАЛИЗ
// =============================================================================

void testContextAnalysis() {
  // ok: sql-injection-sqflite
  final sqlInComment = '-- SELECT * FROM users WHERE id = $userId';

  // ok: sql-injection-sqflite
  final sqlInString = 'Run this query: SELECT * FROM users WHERE id = ?';

  // ok: sql-injection-sqflite
  final sqlInLog = print('Executing: SELECT * FROM users WHERE id = $userId');
}

// ruleid: sql-injection-sqflite
Future<void> testActualVulnerableCode(String userId) async {
  // ruleid: sql-injection-sqflite
  final result = await database.rawQuery('SELECT * FROM users WHERE id = $userId');
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ПЕРЕМЕННЫЕ
// =============================================================================

void _processData(Map<String, dynamic> data) {}

// Глобальные переменные для тестов
String userId = '1';
String email = 'test@example.com';
String name = 'Test User';
String userName = 'TestUser';
String tableName = 'users';
String columnName = 'id';
String value = 'test';
String orderBy = 'created_at';
String whereClause = 'active = 1';
String query = 'SELECT * FROM users';
String userInput = '1 OR 1=1';
String searchTerm = 'test';
String ids = '1,2,3';
String idList = '1,2,3';
String columns = '*';
String table = 'users';
String where = 'id = 1';
String status = 'active';
int id = 1;
int age = 25;
String date = '2024-01-01';
bool condition = true;
bool filter = true;
String direction = 'ASC';
bool shouldEnableJS = true;
Map<String, dynamic> config = {'enableJS': true};