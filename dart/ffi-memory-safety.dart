// test_ffi_memory_safety.dart
// Тест для правила: ffi-memory-safety
// Правило ищет небезопасные вызовы FFI (Foreign Function Interface)
// Все аннотации // ruleid:/ok: размещены непосредственно перед целевыми строками

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// Типизированные typedefs для нативных функций
typedef NativeProcess = Pointer<Int8> Function(Pointer<Int8> input);
typedef NativeProcessDart = Pointer<Int8> Function(Pointer<Int8> input);

typedef NativeBufferOperation = Void Function(Pointer<Uint8> buffer, Int32 size);
typedef NativeBufferOperationDart = void Function(Pointer<Uint8> buffer, int size);

typedef NativeFree = Void Function(Pointer<Void> ptr);
typedef NativeFreeDart = void Function(Pointer<Void> ptr);

typedef NativeComplexOp = Pointer<Int8> Function(Pointer<Int8> input, Int32 size);
typedef NativeComplexOpDart = Pointer<Int8> Function(Pointer<Int8> input, int size);

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Прямые небезопасные вызовы FFI
// =============================================================================

class UnsafeFFICalls {
  void testUnsafeCall() {
    final DynamicLibrary dylib = DynamicLibrary.open('vulnerable.so');
    final NativeProcessDart func = dylib
        .lookup<NativeFunction<NativeProcess>>('func')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> input = "user input".toNativeUtf8();
    // Нет проверки входных данных
    // ruleid: ffi-memory-safety
    final Pointer<Int8> result = func(input);
    calloc.free(input);
  }

  void testUnsafeCallWithUserInput(String userData) {
    final DynamicLibrary dylib = DynamicLibrary.process();
    final NativeProcessDart func = dylib
        .lookup<NativeFunction<NativeProcess>>('process_string')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> input = userData.toNativeUtf8();
    // Прямая передача пользовательских данных без валидации
    // ruleid: ffi-memory-safety
    final Pointer<Int8> result = func(input);
    calloc.free(input);
  }

  void testUnsafeCallWithFileContent(File file) {
    final DynamicLibrary dylib = DynamicLibrary.open('libnative.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('process_file')
        .asFunction();
    
    final String content = file.readAsStringSync();
    // ruleid: ffi-memory-safety
    final Pointer<Int8> input = content.toNativeUtf8();
    // Данные из файла без проверки
    // ruleid: ffi-memory-safety
    process(input);
    calloc.free(input);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Отсутствие проверки границ буфера
// =============================================================================

class NoBoundaryChecks {
  void testBufferOverflow(List<int> data) {
    final DynamicLibrary dylib = DynamicLibrary.open('libbuffer.so');
    final NativeBufferOperationDart operation = dylib
        .lookup<NativeFunction<NativeBufferOperation>>('write_to_buffer')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(data.length);
    for (int i = 0; i < data.length; i++) {
      buffer[i] = data[i];
    }
    
    // Передаем размер буфера, но не проверяем, что нативная функция его соблюдает
    // ruleid: ffi-memory-safety
    operation(buffer, data.length);
    calloc.free(buffer);
  }

  void testUnsafeStringCopy(String input) {
    final DynamicLibrary dylib = DynamicLibrary.open('libstring.so');
    final NativeProcessDart strcpy = dylib
        .lookup<NativeFunction<NativeProcess>>('strcpy_safe')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> source = input.toNativeUtf8();
    // ruleid: ffi-memory-safety
    final Pointer<Int8> destination = calloc<Int8>(100); // Фиксированный буфер
    
    // Нет проверки, что input не превышает 100 символов
    // ruleid: ffi-memory-safety
    strcpy(destination, source);
    
    calloc.free(source);
    calloc.free(destination);
  }

  void testUnsafeMemoryCopy(Uint8List data) {
    final DynamicLibrary dylib = DynamicLibrary.open('libmem.so');
    final NativeBufferOperationDart memcpy = dylib
        .lookup<NativeFunction<NativeBufferOperation>>('memcpy_unsafe')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Uint8> source = calloc<Uint8>(data.length);
    // ruleid: ffi-memory-safety
    final Pointer<Uint8> destination = calloc<Uint8>(data.length);
    
    final Uint8List sourceList = source.asTypedList(data.length);
    sourceList.setAll(0, data);
    
    // Нет проверки размера destination
    // ruleid: ffi-memory-safety
    memcpy(destination, source, data.length);
    
    calloc.free(source);
    calloc.free(destination);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Use-after-free уязвимости
// =============================================================================

class UseAfterFree {
  void testUseAfterFree() {
    final DynamicLibrary dylib = DynamicLibrary.open('libuse.so');
    final NativeFreeDart free = dylib
        .lookup<NativeFunction<NativeFree>>('free_memory')
        .asFunction();
    final NativeProcessDart use = dylib
        .lookup<NativeFunction<NativeProcess>>('use_memory')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(100);
    // Используем данные
    // ruleid: ffi-memory-safety
    use(data);
    // Освобождаем
    // ruleid: ffi-memory-safety
    free(data.cast());
    // Снова используем после освобождения - use-after-free
    // ruleid: ffi-memory-safety
    use(data);
  }

  void testDoubleFree() {
    final DynamicLibrary dylib = DynamicLibrary.open('libfree.so');
    final NativeFreeDart free = dylib
        .lookup<NativeFunction<NativeFree>>('custom_free')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(50);
    // ruleid: ffi-memory-safety
    free(data.cast());
    // Двойное освобождение
    // ruleid: ffi-memory-safety
    free(data.cast());
  }

  void testUseAfterScope() {
    late Pointer<Int8> data;
    
    {
      // ruleid: ffi-memory-safety
      data = calloc<Int8>(100);
      final Pointer<Int8> temp = "data".toNativeUtf8().cast<Int8>();
      for (int i = 0; i < 100 && temp[i] != 0; i++) {
        data[i] = temp[i];
      }
      calloc.free(temp);
    } // data выходит из области видимости, но память не освобождена
    
    final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('process')
        .asFunction();
    
    // Используем data после того, как она должна была быть освобождена
    // ruleid: ffi-memory-safety
    process(data);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Неправильное управление памятью
// =============================================================================

class ImproperMemoryManagement {
  void testMemoryLeak(String input) {
    final DynamicLibrary dylib = DynamicLibrary.open('libleak.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('allocate_and_process')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = input.toNativeUtf8();
    // ruleid: ffi-memory-safety
    final Pointer<Int8> result = process(data);
    // Освобождаем только исходные данные, но не результат
    calloc.free(data);
    // result никогда не освобождается - утечка памяти
  }

  void testIncorrectFree() {
    final DynamicLibrary dylib = DynamicLibrary.open('libwrong.so');
    final NativeFreeDart customFree = dylib
        .lookup<NativeFunction<NativeFree>>('custom_deallocator')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(200);
    // Используем неправильную функцию для освобождения
    // ruleid: ffi-memory-safety
    customFree(data.cast());
  }

  void testPartialFree() {
    final DynamicLibrary dylib = DynamicLibrary.open('libpartial.so');
    final NativeComplexOpDart operation = dylib
        .lookup<NativeFunction<NativeComplexOp>>('complex_operation')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(1000);
    // ruleid: ffi-memory-safety
    final Pointer<Int8> result = operation(data, 1000);
    
    // Освобождаем только часть структуры
    calloc.free(data);
    // result может содержать указатели на внутренние структуры
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Отсутствие валидации входных данных
// =============================================================================

class NoInputValidation {
  void testNoSizeValidation(String data) {
    final DynamicLibrary dylib = DynamicLibrary.open('libvalidate.so');
    final NativeComplexOpDart process = dylib
        .lookup<NativeFunction<NativeComplexOp>>('process_with_size')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> input = data.toNativeUtf8();
    // Передаем размер, но не проверяем, что нативная функция его соблюдает
    // и не валидируем содержимое input
    // ruleid: ffi-memory-safety
    final Pointer<Int8> result = process(input, data.length);
    calloc.free(input);
  }

  void testNoNullTerminatorCheck(String input) {
    final DynamicLibrary dylib = DynamicLibrary.open('libstring.so');
    final NativeProcessDart strlen = dylib
        .lookup<NativeFunction<NativeProcess>>('custom_strlen')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(input.length); // Нет места для null-terminator
    for (int i = 0; i < input.length; i++) {
      data[i] = input.codeUnitAt(i);
    }
    
    // Нативная функция ожидает null-terminated string
    // Но мы не добавили null-terminator
    // ruleid: ffi-memory-safety
    strlen(data);
    calloc.free(data);
  }

  void testNegativeSize() {
    final DynamicLibrary dylib = DynamicLibrary.open('libnegative.so');
    final NativeComplexOpDart operation = dylib
        .lookup<NativeFunction<NativeComplexOp>>('operation_with_size')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(100);
    // Передаем отрицательный размер, нативная функция может его не проверить
    // ruleid: ffi-memory-safety
    operation(data, -1);
    calloc.free(data);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасное использование asTypedList
// =============================================================================

class UnsafeTypedListUsage {
  void testUnsafeTypedList() {
    // ruleid: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(100);
    
    // Создаем view на всю память
    // ruleid: ffi-memory-safety
    final Uint8List view = buffer.asTypedList(100);
    
    // Модифицируем через view - выход за границы!
    for (int i = 0; i < 200; i++) {
      view[i] = i.toInt();
    }
    
    final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
    final NativeBufferOperationDart process = dylib
        .lookup<NativeFunction<NativeBufferOperation>>('process_buffer')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    process(buffer, 100);
    calloc.free(buffer);
  }

  void testUnsafeTypedListView(String data) {
    // ruleid: ffi-memory-safety
    final Pointer<Int8> ptr = data.toNativeUtf8();
    final int length = data.length;
    
    // Создаем view, который может быть изменен
    // ruleid: ffi-memory-safety
    final Uint8List view = ptr.cast<Uint8>().asTypedList(length);
    
    // Модифицируем память напрямую
    for (int i = 0; i < length; i++) {
      view[i] = 0; // Затираем данные
    }
    
    // ptr теперь указывает на испорченные данные
    calloc.free(ptr);
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасные вызовы в циклах и обработчиках
// =============================================================================

class LoopAndCallbackIssues {
  void testUnsafeCallsInLoop(List<String> inputs) {
    final DynamicLibrary dylib = DynamicLibrary.open('libloop.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('process')
        .asFunction();
    
    for (final String input in inputs) {
      // ruleid: ffi-memory-safety
      final Pointer<Int8> data = input.toNativeUtf8();
      // Многократные вызовы без проверки
      // ruleid: ffi-memory-safety
      final Pointer<Int8> result = process(data);
      calloc.free(data);
      // Утечка result в каждой итерации
    }
  }
}

// =============================================================================
// ПОЗИТИВНЫЕ ТЕСТЫ: Небезопасное использование с внешними библиотеками
// =============================================================================

class ExternalLibraryIssues {
  void testOpenSSLCall(String userInput) {
    final DynamicLibrary dylib = DynamicLibrary.open('libssl.so');
    final NativeProcessDart encrypt = dylib
        .lookup<NativeFunction<NativeProcess>>('EVP_Encrypt')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = userInput.toNativeUtf8();
    // Прямой вызов OpenSSL без проверок
    // ruleid: ffi-memory-safety
    final Pointer<Int8> encrypted = encrypt(data);
    
    // Может быть use-after-free или buffer overflow в OpenSSL
    calloc.free(data);
  }

  void testSQLiteCall(String query) {
    final DynamicLibrary dylib = DynamicLibrary.open('libsqlite3.so');
    final NativeProcessDart prepare = dylib
        .lookup<NativeFunction<NativeProcess>>('sqlite3_prepare_v2')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> sql = query.toNativeUtf8();
    // Прямая передача SQL запроса без валидации
    // ruleid: ffi-memory-safety
    prepare(sql);
    calloc.free(sql);
  }

  void testLibCalls(String input) {
    final DynamicLibrary dylib = DynamicLibrary.process(); // libc
    final NativeProcessDart strdup = dylib
        .lookup<NativeFunction<NativeProcess>>('strdup')
        .asFunction();
    
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = input.toNativeUtf8();
    // strdup выделяет память, которую нужно освободить через free
    // ruleid: ffi-memory-safety
    final Pointer<Int8> duplicated = strdup(data);
    
    // Забываем освободить duplicated - утечка памяти
    calloc.free(data);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Безопасные вызовы с валидацией
// =============================================================================

class SafeFFICalls {
  void testSafeCallWithValidation(String userInput) {
    final DynamicLibrary dylib = DynamicLibrary.open('libsafe.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('safe_process')
        .asFunction();
    
    // Валидация входных данных
    if (userInput.length > 1024) {
      throw Exception('Input too long');
    }
    
    if (!RegExp(r'^[a-zA-Z0-9]+$').hasMatch(userInput)) {
      throw Exception('Invalid characters');
    }
    
    // ok: ffi-memory-safety
    final Pointer<Int8> input = userInput.toNativeUtf8();
    // ok: ffi-memory-safety
    final Pointer<Int8> result = process(input);
    
    // Проверка результата
    if (result == nullptr) {
      calloc.free(input);
      throw Exception('Processing failed');
    }
    
    // Освобождение памяти
    calloc.free(input);
    calloc.free(result);
  }

  void testSafeBufferOperation(Uint8List data) {
    final DynamicLibrary dylib = DynamicLibrary.open('libbuffer.so');
    final NativeBufferOperationDart operation = dylib
        .lookup<NativeFunction<NativeBufferOperation>>('safe_buffer_op')
        .asFunction();
    
    // Проверка размера
    if (data.length > 4096) {
      throw Exception('Buffer too large');
    }
    
    // ok: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(data.length);
    final Uint8List bufferList = buffer.asTypedList(data.length);
    bufferList.setAll(0, data);
    
    // Безопасный вызов с проверкой размера
    // ok: ffi-memory-safety
    operation(buffer, data.length);
    
    calloc.free(buffer);
  }

  void testSafeMemoryManagement() {
    final DynamicLibrary dylib = DynamicLibrary.open('libmem.so');
    final NativeComplexOpDart operation = dylib
        .lookup<NativeFunction<NativeComplexOp>>('safe_operation')
        .asFunction();
    
    // ok: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(100);
    try {
      // ok: ffi-memory-safety
      final Pointer<Int8> result = operation(data, 100);
      if (result != nullptr) {
        // Используем результат
        calloc.free(result);
      }
    } finally {
      // Гарантированное освобождение
      calloc.free(data);
    }
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование calloc с явной очисткой
// =============================================================================

class SafeMemoryAllocation {
  void testCallocWithCleanup() {
    // ok: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(1024);
    
    try {
      // Инициализация буфера
      for (int i = 0; i < 1024; i++) {
        buffer[i] = 0;
      }
      
      final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
      final NativeBufferOperationDart process = dylib
          .lookup<NativeFunction<NativeBufferOperation>>('process')
          .asFunction();
      
      // ok: ffi-memory-safety
      process(buffer, 1024);
    } finally {
      // Явная очистка перед освобождением
      for (int i = 0; i < 1024; i++) {
        buffer[i] = 0;
      }
      calloc.free(buffer);
    }
  }

  void testCallocWithSensitiveData(String sensitive) {
    // ok: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(sensitive.length + 1);
    
    try {
      // Копируем данные
      for (int i = 0; i < sensitive.length; i++) {
        data[i] = sensitive.codeUnitAt(i);
      }
      data[sensitive.length] = 0; // null terminator
      
      final DynamicLibrary dylib = DynamicLibrary.open('libcrypto.so');
      final NativeProcessDart encrypt = dylib
          .lookup<NativeFunction<NativeProcess>>('encrypt')
          .asFunction();
      
      // ok: ffi-memory-safety
      final Pointer<Int8> encrypted = encrypt(data);
      
      // Используем зашифрованные данные
      calloc.free(encrypted);
    } finally {
      // Затираем чувствительные данные перед освобождением
      for (int i = 0; i < sensitive.length + 1; i++) {
        data[i] = 0;
      }
      calloc.free(data);
    }
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Проверка границ буфера
// =============================================================================

class BoundaryChecks {
  void testSafeStringCopy(String input) {
    const int MAX_SIZE = 100;
    
    if (input.length >= MAX_SIZE) {
      throw Exception('Input too long');
    }
    
    final DynamicLibrary dylib = DynamicLibrary.open('libstring.so');
    final NativeProcessDart strcpy = dylib
        .lookup<NativeFunction<NativeProcess>>('safe_strcpy')
        .asFunction();
    
    // ok: ffi-memory-safety
    final Pointer<Int8> source = input.toNativeUtf8();
    // ok: ffi-memory-safety
    final Pointer<Int8> destination = calloc<Int8>(MAX_SIZE);
    
    // Проверка перед копированием
    if (input.length < MAX_SIZE) {
      // ok: ffi-memory-safety
      strcpy(destination, source);
    }
    
    calloc.free(source);
    calloc.free(destination);
  }

  void testSafeBufferAccess(Uint8List data) {
    const int MAX_BUFFER = 4096;
    
    if (data.length > MAX_BUFFER) {
      throw Exception('Buffer overflow risk');
    }
    
    // ok: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(MAX_BUFFER);
    
    // Безопасное копирование с проверкой границ
    for (int i = 0; i < data.length && i < MAX_BUFFER; i++) {
      buffer[i] = data[i];
    }
    
    final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
    final NativeBufferOperationDart process = dylib
        .lookup<NativeFunction<NativeBufferOperation>>('process')
        .asFunction();
    
    // ok: ffi-memory-safety
    process(buffer, data.length);
    calloc.free(buffer);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Правильное использование asTypedList
// =============================================================================

class SafeTypedListUsage {
  void testSafeTypedListView(Pointer<Uint8> ptr, int size) {
    if (size <= 0 || size > 1024) {
      throw Exception('Invalid size');
    }
    
    // Создаем view только на валидный диапазон
    // ok: ffi-memory-safety
    final Uint8List view = ptr.asTypedList(size);
    
    // Только чтение, не модификация
    for (int i = 0; i < view.length; i++) {
      print(view[i]);
    }
  }

  void testSafeTypedListModification() {
    // ok: ffi-memory-safety
    final Pointer<Uint8> buffer = calloc<Uint8>(100);
    
    try {
      // ok: ffi-memory-safety
      final Uint8List view = buffer.asTypedList(100);
      
      // Безопасная модификация в пределах размера
      for (int i = 0; i < view.length; i++) {
        view[i] = i.toInt();
      }
    } finally {
      calloc.free(buffer);
    }
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Проверка null-terminator
// =============================================================================

class NullTerminatorChecks {
  void testSafeStringHandling(String input) {
    final DynamicLibrary dylib = DynamicLibrary.open('libstring.so');
    final NativeProcessDart strlen = dylib
        .lookup<NativeFunction<NativeProcess>>('strlen')
        .asFunction();
    
    // Выделяем память с местом для null-terminator
    // ok: ffi-memory-safety
    final Pointer<Int8> data = calloc<Int8>(input.length + 1);
    
    // Копируем строку и добавляем null-terminator
    for (int i = 0; i < input.length; i++) {
      data[i] = input.codeUnitAt(i);
    }
    data[input.length] = 0;
    
    // Безопасный вызов
    // ok: ffi-memory-safety
    strlen(data);
    
    calloc.free(data);
  }
}

// =============================================================================
// НЕГАТИВНЫЕ ТЕСТЫ: Использование FFI с аллокаторами Dart
// =============================================================================

class SafeDartAllocators {
  void testUsingMalloc() {
    final DynamicLibrary dylib = DynamicLibrary.process();
    final Pointer<NativeFunction<Pointer<Void> Function(IntPtr)>> mallocFunc = 
        dylib.lookup('malloc');
    final Pointer<NativeFunction<Void Function(Pointer<Void>)>> freeFunc = 
        dylib.lookup('free');
    
    // Выделяем память через malloc
    // ok: ffi-memory-safety
    final Pointer<Void> ptr = mallocFunc
        .cast<NativeFunction<Pointer<Void> Function(IntPtr)>>()
        .asFunction<Pointer<Void> Function(int)>()(100);
    
    try {
      // Используем память
      final Pointer<Uint8> buffer = ptr.cast<Uint8>();
      for (int i = 0; i < 100; i++) {
        buffer[i] = i.toInt();
      }
    } finally {
      // Освобождаем через free
      // ok: ffi-memory-safety
      freeFunc
          .cast<NativeFunction<Void Function(Pointer<Void>)>>()
          .asFunction<void Function(Pointer<Void>)>()(ptr);
    }
  }

  void testUsingCalloc() {
    // calloc уже безопасен, так как инициализирует память нулями
    // ok: ffi-memory-safety
    final Pointer<Int8> ptr = calloc<Int8>(50);
    
    try {
      // Используем память
      for (int i = 0; i < 50; i++) {
        ptr[i]; // Просто читаем
      }
    } finally {
      // ok: ffi-memory-safety
      calloc.free(ptr);
    }
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Частичная валидация
// =============================================================================

class PartialValidation {
  void testPartialValidation(String input) {
    final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
    final NativeProcessDart process = dylib
        .lookup<NativeFunction<NativeProcess>>('process')
        .asFunction();
    
    // Недостаточная валидация - только проверка длины
    if (input.length > 100) {
      throw Exception('Too long');
    }
    
    // Нет проверки содержимого
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = input.toNativeUtf8();
    // ruleid: ffi-memory-safety
    process(data);
    calloc.free(data);
  }

  void testValidationAfterAllocation(String input) {
    // ruleid: ffi-memory-safety
    final Pointer<Int8> data = input.toNativeUtf8();
    
    // Валидация после выделения памяти
    if (input.contains('<script>')) {
      // Память уже выделена, но мы все равно используем data
      final DynamicLibrary dylib = DynamicLibrary.open('lib.so');
      final NativeProcessDart process = dylib
          .lookup<NativeFunction<NativeProcess>>('process')
          .asFunction();
      
      // ruleid: ffi-memory-safety
      process(data);
    }
    
    calloc.free(data);
  }
}

// =============================================================================
// ГРАНИЧНЫЕ СЛУЧАИ: Сложные структуры данных
// =============================================================================

class ComplexStructIssues {
  void testUnsafeStructPassing() {
    final DynamicLibrary dylib = DynamicLibrary.open('libstruct.so');
    
    // Предположим, что нативная функция ожидает указатель на структуру
    typedef NativeProcessStruct = Pointer<Void> Function(Pointer<Void> input);
    typedef ProcessStructDart = Pointer<Void> Function(Pointer<Void> input);
    
    final ProcessStructDart process = dylib
        .lookup<NativeFunction<NativeProcessStruct>>('process_struct')
        .asFunction();
    
    // Создаем структуру вручную (небезопасно)
    // ruleid: ffi-memory-safety
    final Pointer<Uint8> struct = calloc<Uint8>(32);
    
    // Заполняем структуру без проверки смещений
    struct[0] = 1; // type
    struct[4] = 2; // flags
    
    // ruleid: ffi-memory-safety
    final Pointer<Void> result = process(struct.cast());
    calloc.free(struct);
  }
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// =============================================================================

extension PointerUtils on Pointer<Int8> {
  String toDartString() {
    return this.cast<Utf8>().toDartString();
  }
}