// test_race_condition.c
// Comprehensive test suite for CWE-366/CWE-367: Race Condition detection
// Compile with: gcc -Wall -Wextra -std=c11 -pthread test_race_condition.c -o test_race
// C++ Compile: g++ -Wall -Wextra -std=c++17 -pthread test_race_condition.c -o test_race

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <wchar.h>

#ifdef __cplusplus
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>
#include <iostream>
#endif

// ============================================================================
// GLOBAL AND SHARED VARIABLES
// ============================================================================

static int global_counter = 0;
static int shared_data = 0;
static int g_config_value = 0;
static char *shared_buffer = NULL;
static FILE *shared_log = NULL;
static int connection_count = 0;

#ifdef __cplusplus
static int cpp_shared_counter = 0;
static std::shared_ptr<int> cpp_shared_ptr;
#endif

// ============================================================================
// SYNCHRONIZATION PRIMATIVES
// ============================================================================

pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t buffer_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef __cplusplus
static std::mutex cpp_mutex;
static std::atomic<int> atomic_counter(0);
#endif

// ============================================================================
// SECTION 1: TOCTOU - ACCESS THEN OPEN
// ============================================================================

void test_toctou_access_fopen_vulnerable(char *filepath) {
    // ruleid: Possible-Race-Condition
    if (access(filepath, R_OK) == 0) {
        // ruleid: Possible-Race-Condition
        FILE *f = fopen(filepath, "r");
        if (f) {
            char buf[256];
            fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
}

void test_toctou_access_open_vulnerable(char *filepath) {
    // ruleid: Possible-Race-Condition
    if (access(filepath, F_OK) == 0) {
        // ruleid: Possible-Race-Condition
        int fd = open(filepath, O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

void test_toctou_stat_unlink_vulnerable(char *filepath) {
    struct stat st;
    // ruleid: Possible-Race-Condition
    if (stat(filepath, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            // ruleid: Possible-Race-Condition
            unlink(filepath);
        }
    }
}

void test_toctou_access_mkdir_vulnerable(char *dirpath) {
    // ruleid: Possible-Race-Condition
    if (access(dirpath, F_OK) != 0) {
        // ruleid: Possible-Race-Condition
        mkdir(dirpath, 0755);
    }
}

void test_toctou_lstat_rename_vulnerable(char *oldpath, char *newpath) {
    struct stat st;
    // ruleid: Possible-Race-Condition
    if (lstat(oldpath, &st) == 0) {
        // ruleid: Possible-Race-Condition
        rename(oldpath, newpath);
    }
}

void test_toctou_safe_with_mutex(char *filepath) {
    pthread_mutex_lock(&counter_mutex);
    // ok: Possible-Race-Condition
    if (access(filepath, R_OK) == 0) {
        // ok: Possible-Race-Condition
        FILE *f = fopen(filepath, "r");
        if (f) fclose(f);
    }
    pthread_mutex_unlock(&counter_mutex);
}

void test_toctou_safe_with_lockguard(char *filepath) {
#ifdef __cplusplus
    std::lock_guard<std::mutex> lock(cpp_mutex);
    // ok: Possible-Race-Condition
    if (access(filepath, R_OK) == 0) {
        // ok: Possible-Race-Condition
        FILE *f = fopen(filepath, "r");
        if (f) fclose(f);
    }
#endif
}

// ============================================================================
// SECTION 2: NON-ATOMIC OPERATIONS ON SHARED VARIABLES
// ============================================================================

void test_nonatomic_increment_vulnerable() {
    // ruleid: Possible-Race-Condition
    global_counter++;
}

void test_nonatomic_decrement_vulnerable() {
    // ruleid: Possible-Race-Condition
    global_counter--;
}

void test_nonatomic_preincrement_vulnerable() {
    // ruleid: Possible-Race-Condition
    ++shared_data;
}

void test_nonatomic_predecrement_vulnerable() {
    // ruleid: Possible-Race-Condition
    --shared_data;
}

void test_nonatomic_compound_assignment_vulnerable(int value) {
    // ruleid: Possible-Race-Condition
    g_config_value += value;
}

void test_nonatomic_subtraction_vulnerable(int value) {
    // ruleid: Possible-Race-Condition
    connection_count -= value;
}

void test_nonatomic_safe_with_mutex() {
    pthread_mutex_lock(&counter_mutex);
    // ok: Possible-Race-Condition
    global_counter++;
    pthread_mutex_unlock(&counter_mutex);
}

void test_nonatomic_safe_with_lockguard() {
#ifdef __cplusplus
    std::lock_guard<std::mutex> lock(cpp_mutex);
    // ok: Possible-Race-Condition
    cpp_shared_counter++;
#endif
}

void test_nonatomic_safe_with_atomic() {
#ifdef __cplusplus
    // ok: Possible-Race-Condition
    atomic_counter++;
#endif
}

// ============================================================================
// SECTION 3: SINGLETON RACE CONDITION
// ============================================================================

typedef struct {
    int id;
    char name[64];
} Singleton;

static Singleton *singleton_instance = NULL;

Singleton *get_singleton_vulnerable() {
    // ruleid: Possible-Race-Condition
    if (!singleton_instance) {
        // ruleid: Possible-Race-Condition
        singleton_instance = (Singleton *)malloc(sizeof(Singleton));
        if (singleton_instance) {
            singleton_instance->id = 1;
            strcpy(singleton_instance->name, "default");
        }
    }
    return singleton_instance;
}

Singleton *get_singleton_safe() {
    pthread_mutex_lock(&counter_mutex);
    // ok: Possible-Race-Condition
    if (!singleton_instance) {
        // ok: Possible-Race-Condition
        singleton_instance = (Singleton *)malloc(sizeof(Singleton));
        if (singleton_instance) {
            singleton_instance->id = 1;
            strcpy(singleton_instance->name, "default");
        }
    }
    pthread_mutex_unlock(&counter_mutex);
    return singleton_instance;
}

#ifdef __cplusplus
class CppSingleton {
private:
    static CppSingleton *instance;
    static std::mutex mtx;
    CppSingleton() {}
public:
    static CppSingleton *getInstance_vulnerable() {
        // ruleid: Possible-Race-Condition
        if (!instance) {
            // ruleid: Possible-Race-Condition
            instance = new CppSingleton();
        }
        return instance;
    }
    
    static CppSingleton *getInstance_safe() {
        std::lock_guard<std::mutex> lock(mtx);
        // ok: Possible-Race-Condition
        if (!instance) {
            // ok: Possible-Race-Condition
            instance = new CppSingleton();
        }
        return instance;
    }
};

CppSingleton *CppSingleton::instance = nullptr;
std::mutex CppSingleton::mtx;
#endif

// ============================================================================
// SECTION 4: THREAD CREATION WITHOUT SYNCHRONIZATION
// ============================================================================

void *thread_worker_vulnerable(void *arg) {
    // ruleid: Possible-Race-Condition
    shared_data = *(int *)arg;
    return NULL;
}

void test_thread_creation_vulnerable(int *data) {
    pthread_t thread;
    // ruleid: Possible-Race-Condition
    pthread_create(&thread, NULL, thread_worker_vulnerable, data);
    pthread_join(thread, NULL);
}

#ifdef __cplusplus
void cpp_thread_worker_vulnerable(int *data) {
    // ruleid: Possible-Race-Condition
    cpp_shared_counter = *data;
}

void test_cpp_thread_creation_vulnerable(int *data) {
    // ruleid: Possible-Race-Condition
    std::thread t(cpp_thread_worker_vulnerable, data);
    t.join();
}
#endif

void test_thread_creation_safe(int *data) {
    pthread_mutex_lock(&data_mutex);
    pthread_t thread;
    // ok: Possible-Race-Condition
    pthread_create(&thread, NULL, thread_worker_vulnerable, data);
    pthread_mutex_unlock(&data_mutex);
    pthread_join(thread, NULL);
}

// ============================================================================
// SECTION 5: CHECK-THEN-ACT PATTERNS
// ============================================================================

void test_check_then_free_vulnerable(char *ptr, int condition) {
    if (ptr != NULL) {
        if (condition) {
            // ruleid: Possible-Race-Condition
            free(ptr);
        }
    }
    // ruleid: Possible-Race-Condition
    if (ptr != NULL) {
        printf("Data: %s\n", ptr);
    }
}

void test_check_then_act_vulnerable(int *value) {
    // ruleid: Possible-Race-Condition
    if (value != NULL) {
        // Some other thread might free here
        // ruleid: Possible-Race-Condition
        printf("Value: %d\n", *value);
    }
}

void test_check_then_act_safe(int *value) {
    pthread_mutex_lock(&data_mutex);
    // ok: Possible-Race-Condition
    if (value != NULL) {
        // ok: Possible-Race-Condition
        printf("Value: %d\n", *value);
    }
    pthread_mutex_unlock(&data_mutex);
}

// ============================================================================
// SECTION 6: DOUBLE FREE SCENARIOS
// ============================================================================

void test_double_free_vulnerable(char *buffer, int flag) {
    if (flag) {
        // ruleid: Possible-Race-Condition
        free(buffer);
    }
    // ruleid: Possible-Race-Condition
    free(buffer);
}

void test_double_close_vulnerable(int fd, int condition) {
    if (condition) {
        // ruleid: Possible-Race-Condition
        close(fd);
    }
    // ruleid: Possible-Race-Condition
    close(fd);
}

void test_double_fclose_vulnerable(FILE *fp, int flag) {
    if (flag) {
        // ruleid: Possible-Race-Condition
        fclose(fp);
    }
    // ruleid: Possible-Race-Condition
    fclose(fp);
}

void test_double_free_safe(char *buffer, int flag) {
    pthread_mutex_lock(&buffer_mutex);
    if (flag) {
        // ok: Possible-Race-Condition
        free(buffer);
        buffer = NULL;
    }
    pthread_mutex_unlock(&buffer_mutex);
}

// ============================================================================
// SECTION 7: SIGNAL HANDLER RACE CONDITIONS
// ============================================================================

static volatile sig_atomic_t signal_flag = 0;
static char signal_buffer[256];

void signal_handler_vulnerable(int sig) {
    // ruleid: Possible-Race-Condition
    strcpy(signal_buffer, "signal received");
    // ruleid: Possible-Race-Condition
    signal_flag = 1;
}

void test_signal_registration_vulnerable() {
    // ruleid: Possible-Race-Condition
    signal(SIGINT, signal_handler_vulnerable);
    // ruleid: Possible-Race-Condition
    signal(SIGTERM, signal_handler_vulnerable);
}

void signal_handler_safe(int sig) {
    // ok: Possible-Race-Condition
    signal_flag = 1;
}

void test_signal_registration_safe() {
    pthread_mutex_lock(&counter_mutex);
    // ok: Possible-Race-Condition
    signal(SIGINT, signal_handler_safe);
    pthread_mutex_unlock(&counter_mutex);
}

// ============================================================================
// SECTION 8: ENVIRONMENT VARIABLE RACE CONDITIONS
// ============================================================================

void test_setenv_vulnerable(char *var_name, char *var_value) {
    // ruleid: Possible-Race-Condition
    setenv(var_name, var_value, 1);
}

void test_putenv_vulnerable(char *env_string) {
    // ruleid: Possible-Race-Condition
    putenv(env_string);
}

void test_unsetenv_vulnerable(char *var_name) {
    // ruleid: Possible-Race-Condition
    unsetenv(var_name);
}

void test_environment_safe() {
    pthread_mutex_lock(&data_mutex);
    // ok: Possible-Race-Condition
    setenv("APP_MODE", "production", 1);
    // ok: Possible-Race-Condition
    putenv("DEBUG=false");
    pthread_mutex_unlock(&data_mutex);
}

// ============================================================================
// SECTION 9: SHARED RESOURCE ACCESS IN THREADS
// ============================================================================

void *reader_thread_vulnerable(void *arg) {
    // ruleid: Possible-Race-Condition
    int value = shared_data;
    printf("Reader: %d\n", value);
    return NULL;
}

void *writer_thread_vulnerable(void *arg) {
    // ruleid: Possible-Race-Condition
    shared_data = *(int *)arg;
    return NULL;
}

void *reader_writer_vulnerable(void *arg) {
    // ruleid: Possible-Race-Condition
    shared_data++;
    // ruleid: Possible-Race-Condition
    printf("Value: %d\n", shared_data);
    return NULL;
}

void *reader_thread_safe(void *arg) {
    pthread_mutex_lock(&data_mutex);
    // ok: Possible-Race-Condition
    int value = shared_data;
    printf("Reader: %d\n", value);
    pthread_mutex_unlock(&data_mutex);
    return NULL;
}

void *writer_thread_safe(void *arg) {
    pthread_mutex_lock(&data_mutex);
    // ok: Possible-Race-Condition
    shared_data = *(int *)arg;
    pthread_mutex_unlock(&data_mutex);
    return NULL;
}

// ============================================================================
// SECTION 10: FILE DESCRIPTOR SHARING
// ============================================================================

static int shared_fd = -1;

void test_shared_fd_write_vulnerable(const char *data) {
    // ruleid: Possible-Race-Condition
    write(shared_fd, data, strlen(data));
}

void test_shared_fd_read_vulnerable(char *buffer, size_t size) {
    // ruleid: Possible-Race-Condition
    read(shared_fd, buffer, size);
}

void test_shared_fd_safe(const char *data) {
    pthread_mutex_lock(&buffer_mutex);
    // ok: Possible-Race-Condition
    write(shared_fd, data, strlen(data));
    pthread_mutex_unlock(&buffer_mutex);
}

// ============================================================================
// SECTION 11: C++ SPECIFIC PATTERNS
// ============================================================================

#ifdef __cplusplus

class SharedResource {
private:
    int value;
    std::string data;
    
public:
    void increment_vulnerable() {
        // ruleid: Possible-Race-Condition
        value++;
    }
    
    void increment_safe() {
        std::lock_guard<std::mutex> lock(cpp_mutex);
        // ok: Possible-Race-Condition
        value++;
    }
    
    void setData_vulnerable(const std::string& new_data) {
        // ruleid: Possible-Race-Condition
        data = new_data;
    }
    
    void setData_safe(const std::string& new_data) {
        std::lock_guard<std::mutex> lock(cpp_mutex);
        // ok: Possible-Race-Condition
        data = new_data;
    }
    
    std::string getData_vulnerable() {
        // ruleid: Possible-Race-Condition
        return data;
    }
    
    std::string getData_safe() {
        std::lock_guard<std::mutex> lock(cpp_mutex);
        // ok: Possible-Race-Condition
        return data;
    }
};

void test_atomic_operations_safe() {
    static std::atomic<int> atomic_var(0);
    // ok: Possible-Race-Condition
    atomic_var++;
    // ok: Possible-Race-Condition
    atomic_var--;
    // ok: Possible-Race-Condition
    atomic_var += 5;
}

void test_atomic_operations_vulnerable() {
    static int regular_var = 0;
    // ruleid: Possible-Race-Condition
    regular_var++;
    // ruleid: Possible-Race-Condition
    regular_var--;
}

#endif

// ============================================================================
// SECTION 12: REAL-WORLD SCENARIO - CONNECTION POOL
// ============================================================================

typedef struct {
    int *connections;
    int max_connections;
    int active_count;
    pthread_mutex_t pool_mutex;
} ConnectionPool;

ConnectionPool *create_pool(int max) {
    ConnectionPool *pool = malloc(sizeof(ConnectionPool));
    pool->connections = malloc(sizeof(int) * max);
    pool->max_connections = max;
    pool->active_count = 0;
    pthread_mutex_init(&pool->pool_mutex, NULL);
    return pool;
}

int get_connection_vulnerable(ConnectionPool *pool) {
    // ruleid: Possible-Race-Condition
    if (pool->active_count < pool->max_connections) {
        // ruleid: Possible-Race-Condition
        pool->active_count++;
        return pool->active_count - 1;
    }
    return -1;
}

int get_connection_safe(ConnectionPool *pool) {
    pthread_mutex_lock(&pool->pool_mutex);
    // ok: Possible-Race-Condition
    if (pool->active_count < pool->max_connections) {
        // ok: Possible-Race-Condition
        pool->active_count++;
        pthread_mutex_unlock(&pool->pool_mutex);
        return pool->active_count - 1;
    }
    pthread_mutex_unlock(&pool->pool_mutex);
    return -1;
}

void release_connection_vulnerable(ConnectionPool *pool, int conn_id) {
    // ruleid: Possible-Race-Condition
    pool->active_count--;
}

void release_connection_safe(ConnectionPool *pool, int conn_id) {
    pthread_mutex_lock(&pool->pool_mutex);
    // ok: Possible-Race-Condition
    pool->active_count--;
    pthread_mutex_unlock(&pool->pool_mutex);
}

// ============================================================================
// SECTION 13: REAL-WORLD SCENARIO - LOGGING SYSTEM
// ============================================================================

typedef struct {
    FILE *log_file;
    pthread_mutex_t log_mutex;
    int write_count;
} Logger;

Logger *create_logger(const char *path) {
    Logger *logger = malloc(sizeof(Logger));
    logger->log_file = fopen(path, "a");
    logger->write_count = 0;
    pthread_mutex_init(&logger->log_mutex, NULL);
    return logger;
}

void log_message_vulnerable(Logger *logger, const char *message) {
    // ruleid: Possible-Race-Condition
    if (logger->log_file) {
        // ruleid: Possible-Race-Condition
        fprintf(logger->log_file, "%s\n", message);
        // ruleid: Possible-Race-Condition
        logger->write_count++;
    }
}

void log_message_safe(Logger *logger, const char *message) {
    pthread_mutex_lock(&logger->log_mutex);
    // ok: Possible-Race-Condition
    if (logger->log_file) {
        // ok: Possible-Race-Condition
        fprintf(logger->log_file, "%s\n", message);
        // ok: Possible-Race-Condition
        logger->write_count++;
    }
    pthread_mutex_unlock(&logger->log_mutex);
}

void close_logger_vulnerable(Logger *logger, int force) {
    if (force) {
        // ruleid: Possible-Race-Condition
        fclose(logger->log_file);
    }
    // ruleid: Possible-Race-Condition
    fclose(logger->log_file);
}

void close_logger_safe(Logger *logger, int force) {
    pthread_mutex_lock(&logger->log_mutex);
    if (force && logger->log_file) {
        // ok: Possible-Race-Condition
        fclose(logger->log_file);
        logger->log_file = NULL;
    }
    pthread_mutex_unlock(&logger->log_mutex);
}

// ============================================================================
// SECTION 14: REAL-WORLD SCENARIO - CACHE SYSTEM
// ============================================================================

typedef struct {
    char **cache_keys;
    char **cache_values;
    int cache_size;
    int cache_count;
    pthread_mutex_t cache_mutex;
} Cache;

Cache *create_cache(int size) {
    Cache *cache = malloc(sizeof(Cache));
    cache->cache_keys = malloc(sizeof(char *) * size);
    cache->cache_values = malloc(sizeof(char *) * size);
    cache->cache_size = size;
    cache->cache_count = 0;
    pthread_mutex_init(&cache->cache_mutex, NULL);
    return cache;
}

char *cache_get_vulnerable(Cache *cache, const char *key) {
    // ruleid: Possible-Race-Condition
    for (int i = 0; i < cache->cache_count; i++) {
        // ruleid: Possible-Race-Condition
        if (strcmp(cache->cache_keys[i], key) == 0) {
            // ruleid: Possible-Race-Condition
            return cache->cache_values[i];
        }
    }
    return NULL;
}

void cache_set_vulnerable(Cache *cache, const char *key, const char *value) {
    // ruleid: Possible-Race-Condition
    if (cache->cache_count < cache->cache_size) {
        // ruleid: Possible-Race-Condition
        cache->cache_keys[cache->cache_count] = strdup(key);
        // ruleid: Possible-Race-Condition
        cache->cache_values[cache->cache_count] = strdup(value);
        // ruleid: Possible-Race-Condition
        cache->cache_count++;
    }
}

char *cache_get_safe(Cache *cache, const char *key) {
    pthread_mutex_lock(&cache->cache_mutex);
    // ok: Possible-Race-Condition
    for (int i = 0; i < cache->cache_count; i++) {
        // ok: Possible-Race-Condition
        if (strcmp(cache->cache_keys[i], key) == 0) {
            // ok: Possible-Race-Condition
            char *result = cache->cache_values[i];
            pthread_mutex_unlock(&cache->cache_mutex);
            return result;
        }
    }
    pthread_mutex_unlock(&cache->cache_mutex);
    return NULL;
}

void cache_set_safe(Cache *cache, const char *key, const char *value) {
    pthread_mutex_lock(&cache->cache_mutex);
    // ok: Possible-Race-Condition
    if (cache->cache_count < cache->cache_size) {
        // ok: Possible-Race-Condition
        cache->cache_keys[cache->cache_count] = strdup(key);
        // ok: Possible-Race-Condition
        cache->cache_values[cache->cache_count] = strdup(value);
        // ok: Possible-Race-Condition
        cache->cache_count++;
    }
    pthread_mutex_unlock(&cache->cache_mutex);
}

// ============================================================================
// SECTION 15: EDGE CASES - NESTED LOCKS
// ============================================================================

void test_nested_locks_vulnerable() {
    // ruleid: Possible-Race-Condition
    global_counter++;
    // ruleid: Possible-Race-Condition
    shared_data++;
}

void test_nested_locks_safe() {
    pthread_mutex_lock(&counter_mutex);
    pthread_mutex_lock(&data_mutex);
    // ok: Possible-Race-Condition
    global_counter++;
    // ok: Possible-Race-Condition
    shared_data++;
    pthread_mutex_unlock(&data_mutex);
    pthread_mutex_unlock(&counter_mutex);
}

// ============================================================================
// SECTION 16: EDGE CASES - CONDITIONAL LOCKING
// ============================================================================

void test_conditional_lock_vulnerable(int use_lock) {
    if (use_lock) {
        pthread_mutex_lock(&counter_mutex);
    }
    // ruleid: Possible-Race-Condition
    global_counter++;
    if (use_lock) {
        pthread_mutex_unlock(&counter_mutex);
    }
}

void test_conditional_lock_safe() {
    pthread_mutex_lock(&counter_mutex);
    // ok: Possible-Race-Condition
    global_counter++;
    pthread_mutex_unlock(&counter_mutex);
}

// ============================================================================
// SECTION 17: EDGE CASES - LAZY INITIALIZATION
// ============================================================================

static char *lazy_buffer = NULL;

char *get_lazy_buffer_vulnerable() {
    // ruleid: Possible-Race-Condition
    if (!lazy_buffer) {
        // ruleid: Possible-Race-Condition
        lazy_buffer = malloc(1024);
    }
    return lazy_buffer;
}

char *get_lazy_buffer_safe() {
    pthread_mutex_lock(&buffer_mutex);
    // ok: Possible-Race-Condition
    if (!lazy_buffer) {
        // ok: Possible-Race-Condition
        lazy_buffer = malloc(1024);
    }
    pthread_mutex_unlock(&buffer_mutex);
    return lazy_buffer;
}

// ============================================================================
// SECTION 18: EDGE CASES - REFERENCE COUNTING
// ============================================================================

typedef struct {
    int ref_count;
    char *data;
} RefCounted;

RefCounted *ref_create() {
    RefCounted *obj = malloc(sizeof(RefCounted));
    obj->ref_count = 1;
    obj->data = malloc(256);
    return obj;
}

void ref_acquire_vulnerable(RefCounted *obj) {
    // ruleid: Possible-Race-Condition
    obj->ref_count++;
}

void ref_release_vulnerable(RefCounted *obj) {
    // ruleid: Possible-Race-Condition
    obj->ref_count--;
    // ruleid: Possible-Race-Condition
    if (obj->ref_count == 0) {
        // ruleid: Possible-Race-Condition
        free(obj->data);
        // ruleid: Possible-Race-Condition
        free(obj);
    }
}

void ref_acquire_safe(RefCounted *obj) {
    pthread_mutex_lock(&buffer_mutex);
    // ok: Possible-Race-Condition
    obj->ref_count++;
    pthread_mutex_unlock(&buffer_mutex);
}

void ref_release_safe(RefCounted *obj) {
    pthread_mutex_lock(&buffer_mutex);
    // ok: Possible-Race-Condition
    obj->ref_count--;
    // ok: Possible-Race-Condition
    if (obj->ref_count == 0) {
        // ok: Possible-Race-Condition
        free(obj->data);
        // ok: Possible-Race-Condition
        free(obj);
    }
    pthread_mutex_unlock(&buffer_mutex);
}

// ============================================================================
// SECTION 19: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Race Condition Test Suite\n");
    
    // Safe operations
    test_nonatomic_safe_with_mutex();
    test_toctou_safe_with_mutex("/etc/passwd");
    test_signal_registration_safe();
    test_environment_safe();
    
#ifdef __cplusplus
    test_atomic_operations_safe();
    test_cpp_thread_creation_vulnerable(NULL);
#endif
    
    // Create test resources
    ConnectionPool *pool = create_pool(10);
    Logger *logger = create_logger("/tmp/test.log");
    Cache *cache = create_cache(100);
    
    // Clean up
    free(pool);
    free(logger);
    free(cache);
    
    printf("Test compilation successful\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

static int strcmp(const char *s1, const char *s2) {
    return 0;
}

static char *strdup(const char *s) {
    return (char *)s;
}