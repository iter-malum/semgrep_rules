// test_null_pointer.c
// Comprehensive test suite for CWE-476: NULL Pointer Dereference detection
// Compile with: gcc -Wall -Wextra -std=c11 test_null_pointer.c -o test_null_pointer -lpthread
// C++ Compile: g++ -Wall -Wextra -std=c++17 test_null_pointer.c -o test_null_pointer -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>

#ifdef __cplusplus
#include <memory>
#include <string>
#include <vector>
#include <iostream>
#endif

// ============================================================================
// GLOBAL CONSTANTS AND TYPE DEFINITIONS
// ============================================================================

#define MAX_BUFFER_SIZE 1024
#define MAX_CONNECTIONS 100
#define CONFIG_PATH "/etc/app/config.ini"

typedef struct {
    int id;
    char *name;
    char *email;
    int age;
    void *data;
} User;

typedef struct {
    int socket_fd;
    char *ip_address;
    int port;
    bool is_connected;
    void *session_data;
} Connection;

typedef struct {
    char *db_host;
    int db_port;
    char *db_name;
    char *db_user;
    char *db_password;
    void *db_connection;
} DatabaseConfig;

typedef struct {
    int (*callback)(void *data);
    void *user_data;
    char *description;
} EventHandler;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static User *create_user(const char *name, const char *email, int age) {
    User *user = malloc(sizeof(User));
    if (user) {
        user->id = rand() % 10000;
        user->name = name ? strdup(name) : NULL;
        user->email = email ? strdup(email) : NULL;
        user->age = age;
        user->data = NULL;
    }
    return user;
}

static void free_user(User *user) {
    if (user) {
        free(user->name);
        free(user->email);
        free(user->data);
        free(user);
    }
}

static Connection *create_connection(const char *ip, int port) {
    Connection *conn = malloc(sizeof(Connection));
    if (conn) {
        conn->socket_fd = -1;
        conn->ip_address = ip ? strdup(ip) : NULL;
        conn->port = port;
        conn->is_connected = false;
        conn->session_data = NULL;
    }
    return conn;
}

static void free_connection(Connection *conn) {
    if (conn) {
        free(conn->ip_address);
        free(conn->session_data);
        free(conn);
    }
}

// ============================================================================
// SECTION 1: BASIC NULL POINTER DEREFERENCE - LOCAL VARIABLES
// ============================================================================

void test_basic_null_deref_field_access() {
    User *user = NULL;
    // ruleid: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_basic_null_deref_function_call() {
    Connection *conn = NULL;
    // ruleid: NULL-Pointer-Dereference
    int fd = conn->socket_fd;
    printf("Socket FD: %d\n", fd);
}

void test_basic_null_deref_array_access() {
    int *array = NULL;
    // ruleid: NULL-Pointer-Dereference
    int value = array[0];
    printf("Value: %d\n", value);
}

void test_basic_null_deref_pointer_deref() {
    int *ptr = NULL;
    // ruleid: NULL-Pointer-Dereference
    int value = *ptr;
    printf("Value: %d\n", value);
}

void test_basic_null_safe_with_check() {
    User *user = NULL;
    if (user != NULL) {
        // ok: NULL-Pointer-Dereference
        int id = user->id;
        printf("User ID: %d\n", id);
    }
}

void test_basic_null_safe_with_early_return() {
    User *user = NULL;
    if (user == NULL) {
        return;
    }
    // ok: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_basic_null_safe_with_assert() {
    User *user = NULL;
    assert(user != NULL);
    // ok: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

// ============================================================================
// SECTION 2: FUNCTION PARAMETER NULL DEREFERENCE
// ============================================================================

void test_param_null_deref_field(User *user) {
    // ruleid: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_param_null_deref_function(Connection *conn) {
    // ruleid: NULL-Pointer-Dereference
    printf("Socket: %d\n", conn->socket_fd);
}

void test_param_null_deref_array(int *data, size_t len) {
    // ruleid: NULL-Pointer-Dereference
    int first = data[0];
    printf("First: %d\n", first);
}

void test_param_null_deref_pointer(char *str) {
    // ruleid: NULL-Pointer-Dereference
    printf("Length: %zu\n", strlen(str));
}

void test_param_null_safe_with_check(User *user) {
    if (user != NULL) {
        // ok: NULL-Pointer-Dereference
        int id = user->id;
        printf("User ID: %d\n", id);
    }
}

void test_param_null_safe_with_early_return(User *user) {
    if (user == NULL) {
        fprintf(stderr, "User is NULL\n");
        return;
    }
    // ok: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_param_null_safe_with_assert(User *user) {
    assert(user != NULL);
    // ok: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

// ============================================================================
// SECTION 3: MALLOC/CALLOC WITHOUT NULL CHECK
// ============================================================================

void test_malloc_no_check_field() {
    User *user = malloc(sizeof(User));
    // ruleid: NULL-Pointer-Dereference
    user->id = 123;
    free(user);
}

void test_malloc_no_check_function() {
    char *buffer = malloc(MAX_BUFFER_SIZE);
    // ruleid: NULL-Pointer-Dereference
    strcpy(buffer, "test data");
    free(buffer);
}

void test_malloc_no_check_array() {
    int *array = calloc(100, sizeof(int));
    // ruleid: NULL-Pointer-Dereference
    array[0] = 42;
    free(array);
}

void test_malloc_with_check() {
    User *user = malloc(sizeof(User));
    if (user != NULL) {
        // ok: NULL-Pointer-Dereference
        user->id = 123;
        free(user);
    }
}

void test_malloc_with_early_return() {
    char *buffer = malloc(MAX_BUFFER_SIZE);
    if (buffer == NULL) {
        fprintf(stderr, "Allocation failed\n");
        return;
    }
    // ok: NULL-Pointer-Dereference
    strcpy(buffer, "test data");
    free(buffer);
}

void test_realloc_no_check(char *old_buffer) {
    char *new_buffer = realloc(old_buffer, MAX_BUFFER_SIZE * 2);
    // ruleid: NULL-Pointer-Dereference
    strcpy(new_buffer, "expanded data");
}

void test_realloc_with_check(char *old_buffer) {
    char *new_buffer = realloc(old_buffer, MAX_BUFFER_SIZE * 2);
    if (new_buffer != NULL) {
        // ok: NULL-Pointer-Dereference
        strcpy(new_buffer, "expanded data");
    }
}

// ============================================================================
// SECTION 4: STRING OPERATIONS WITH NULL
// ============================================================================

void test_strcpy_null_dest() {
    char *dest = NULL;
    // ruleid: NULL-Pointer-Dereference
    strcpy(dest, "source string");
}

void test_strcpy_null_src(const char *src) {
    char dest[MAX_BUFFER_SIZE];
    // ruleid: NULL-Pointer-Dereference
    strcpy(dest, src);
}

void test_strcat_null_dest() {
    char *dest = NULL;
    // ruleid: NULL-Pointer-Dereference
    strcat(dest, " appended");
}

void test_memset_null_ptr() {
    void *ptr = NULL;
    // ruleid: NULL-Pointer-Dereference
    memset(ptr, 0, MAX_BUFFER_SIZE);
}

void test_memcpy_null_dest() {
    void *dest = NULL;
    char src[100];
    // ruleid: NULL-Pointer-Dereference
    memcpy(dest, src, sizeof(src));
}

void test_memcpy_null_src() {
    char dest[100];
    void *src = NULL;
    // ruleid: NULL-Pointer-Dereference
    memcpy(dest, src, 100);
}

void test_string_ops_safe() {
    char dest[MAX_BUFFER_SIZE];
    const char *src = "source";
    // ok: NULL-Pointer-Dereference
    strcpy(dest, src);
}

// ============================================================================
// SECTION 5: STRUCT FIELD ASSIGNMENT WITH NULL
// ============================================================================

void test_field_assignment_null() {
    User *user = NULL;
    // ruleid: NULL-Pointer-Dereference
    user->id = 456;
}

void test_field_increment_null() {
    Connection *conn = NULL;
    // ruleid: NULL-Pointer-Dereference
    conn->socket_fd++;
}

void test_field_decrement_null() {
    Connection *conn = NULL;
    // ruleid: NULL-Pointer-Dereference
    conn->port--;
}

void test_field_assignment_safe() {
    User *user = malloc(sizeof(User));
    if (user != NULL) {
        // ok: NULL-Pointer-Dereference
        user->id = 456;
        free(user);
    }
}

// ============================================================================
// SECTION 6: FREE WITH NULL POINTER
// ============================================================================

void test_free_null_pointer() {
    void *ptr = NULL;
    // This is actually safe in C, but some rules flag it
    // ok: NULL-Pointer-Dereference
    free(ptr);
}

void test_free_after_null_assignment() {
    char *buffer = malloc(100);
    buffer = NULL;
    // ok: NULL-Pointer-Dereference (free(NULL) is safe)
    free(buffer);
}

// ============================================================================
// SECTION 7: REAL-WORLD SCENARIO - USER MANAGEMENT SYSTEM
// ============================================================================

typedef struct {
    User **users;
    int count;
    int capacity;
} UserDatabase;

UserDatabase *create_user_database(int capacity) {
    UserDatabase *db = malloc(sizeof(UserDatabase));
    if (db) {
        db->users = malloc(sizeof(User *) * capacity);
        db->count = 0;
        db->capacity = capacity;
    }
    return db;
}

int add_user_vulnerable(UserDatabase *db, const char *name, const char *email) {
    // ruleid: NULL-Pointer-Dereference
    if (db->count >= db->capacity) {
        return -1;
    }
    // ruleid: NULL-Pointer-Dereference
    User *user = create_user(name, email, 0);
    // ruleid: NULL-Pointer-Dereference
    db->users[db->count] = user;
    // ruleid: NULL-Pointer-Dereference
    db->count++;
    return 0;
}

int add_user_safe(UserDatabase *db, const char *name, const char *email) {
    if (db == NULL || db->users == NULL) {
        return -1;
    }
    if (db->count >= db->capacity) {
        return -1;
    }
    // ok: NULL-Pointer-Dereference
    User *user = create_user(name, email, 0);
    // ok: NULL-Pointer-Dereference
    db->users[db->count] = user;
    // ok: NULL-Pointer-Dereference
    db->count++;
    return 0;
}

User *get_user_vulnerable(UserDatabase *db, int id) {
    // ruleid: NULL-Pointer-Dereference
    for (int i = 0; i < db->count; i++) {
        // ruleid: NULL-Pointer-Dereference
        if (db->users[i]->id == id) {
            // ruleid: NULL-Pointer-Dereference
            return db->users[i];
        }
    }
    return NULL;
}

User *get_user_safe(UserDatabase *db, int id) {
    if (db == NULL || db->users == NULL) {
        return NULL;
    }
    // ok: NULL-Pointer-Dereference
    for (int i = 0; i < db->count; i++) {
        // ok: NULL-Pointer-Dereference
        if (db->users[i] != NULL && db->users[i]->id == id) {
            // ok: NULL-Pointer-Dereference
            return db->users[i];
        }
    }
    return NULL;
}

void delete_user_vulnerable(UserDatabase *db, int index) {
    // ruleid: NULL-Pointer-Dereference
    User *user = db->users[index];
    // ruleid: NULL-Pointer-Dereference
    free_user(user);
    // ruleid: NULL-Pointer-Dereference
    db->users[index] = NULL;
    // ruleid: NULL-Pointer-Dereference
    db->count--;
}

void delete_user_safe(UserDatabase *db, int index) {
    if (db == NULL || db->users == NULL) {
        return;
    }
    if (index < 0 || index >= db->count) {
        return;
    }
    // ok: NULL-Pointer-Dereference
    User *user = db->users[index];
    // ok: NULL-Pointer-Dereference
    free_user(user);
    // ok: NULL-Pointer-Dereference
    db->users[index] = NULL;
    // ok: NULL-Pointer-Dereference
    db->count--;
}

// ============================================================================
// SECTION 8: REAL-WORLD SCENARIO - NETWORK CONNECTION HANDLER
// ============================================================================

typedef struct {
    Connection **connections;
    int active_count;
    int max_connections;
    pthread_mutex_t lock;
} ConnectionPool;

ConnectionPool *create_pool(int max) {
    ConnectionPool *pool = malloc(sizeof(ConnectionPool));
    if (pool) {
        pool->connections = malloc(sizeof(Connection *) * max);
        pool->active_count = 0;
        pool->max_connections = max;
        pthread_mutex_init(&pool->lock, NULL);
    }
    return pool;
}

int send_data_vulnerable(ConnectionPool *pool, int conn_id, const char *data) {
    // ruleid: NULL-Pointer-Dereference
    Connection *conn = pool->connections[conn_id];
    // ruleid: NULL-Pointer-Dereference
    if (!conn->is_connected) {
        return -1;
    }
    // ruleid: NULL-Pointer-Dereference
    send(conn->socket_fd, data, strlen(data), 0);
    return 0;
}

int send_data_safe(ConnectionPool *pool, int conn_id, const char *data) {
    if (pool == NULL || pool->connections == NULL) {
        return -1;
    }
    if (conn_id < 0 || conn_id >= pool->max_connections) {
        return -1;
    }
    pthread_mutex_lock(&pool->lock);
    // ok: NULL-Pointer-Dereference
    Connection *conn = pool->connections[conn_id];
    // ok: NULL-Pointer-Dereference
    if (conn != NULL && conn->is_connected) {
        // ok: NULL-Pointer-Dereference
        send(conn->socket_fd, data, strlen(data), 0);
    }
    pthread_mutex_unlock(&pool->lock);
    return 0;
}

void close_all_connections_vulnerable(ConnectionPool *pool) {
    // ruleid: NULL-Pointer-Dereference
    for (int i = 0; i < pool->active_count; i++) {
        // ruleid: NULL-Pointer-Dereference
        Connection *conn = pool->connections[i];
        // ruleid: NULL-Pointer-Dereference
        close(conn->socket_fd);
        // ruleid: NULL-Pointer-Dereference
        free_connection(conn);
        // ruleid: NULL-Pointer-Dereference
        pool->connections[i] = NULL;
    }
    // ruleid: NULL-Pointer-Dereference
    pool->active_count = 0;
}

void close_all_connections_safe(ConnectionPool *pool) {
    if (pool == NULL || pool->connections == NULL) {
        return;
    }
    pthread_mutex_lock(&pool->lock);
    // ok: NULL-Pointer-Dereference
    for (int i = 0; i < pool->active_count; i++) {
        // ok: NULL-Pointer-Dereference
        Connection *conn = pool->connections[i];
        // ok: NULL-Pointer-Dereference
        if (conn != NULL) {
            // ok: NULL-Pointer-Dereference
            close(conn->socket_fd);
            // ok: NULL-Pointer-Dereference
            free_connection(conn);
            // ok: NULL-Pointer-Dereference
            pool->connections[i] = NULL;
        }
    }
    // ok: NULL-Pointer-Dereference
    pool->active_count = 0;
    pthread_mutex_unlock(&pool->lock);
}

// ============================================================================
// SECTION 9: REAL-WORLD SCENARIO - DATABASE CONFIGURATION
// ============================================================================

DatabaseConfig *load_db_config_vulnerable(const char *config_file) {
    DatabaseConfig *config = malloc(sizeof(DatabaseConfig));
    // ruleid: NULL-Pointer-Dereference
    config->db_host = NULL;
    // ruleid: NULL-Pointer-Dereference
    config->db_port = 5432;
    // ruleid: NULL-Pointer-Dereference
    config->db_name = NULL;
    // ruleid: NULL-Pointer-Dereference
    config->db_user = NULL;
    // ruleid: NULL-Pointer-Dereference
    config->db_password = NULL;
    // ruleid: NULL-Pointer-Dereference
    config->db_connection = NULL;
    
    FILE *f = fopen(config_file, "r");
    // ruleid: NULL-Pointer-Dereference
    char line[MAX_BUFFER_SIZE];
    // ruleid: NULL-Pointer-Dereference
    while (fgets(line, sizeof(line), f)) {
        // ruleid: NULL-Pointer-Dereference
        if (strncmp(line, "host=", 5) == 0) {
            // ruleid: NULL-Pointer-Dereference
            config->db_host = strdup(line + 5);
        }
    }
    // ruleid: NULL-Pointer-Dereference
    fclose(f);
    return config;
}

DatabaseConfig *load_db_config_safe(const char *config_file) {
    DatabaseConfig *config = malloc(sizeof(DatabaseConfig));
    if (config == NULL) {
        return NULL;
    }
    // ok: NULL-Pointer-Dereference
    config->db_host = NULL;
    // ok: NULL-Pointer-Dereference
    config->db_port = 5432;
    // ok: NULL-Pointer-Dereference
    config->db_name = NULL;
    // ok: NULL-Pointer-Dereference
    config->db_user = NULL;
    // ok: NULL-Pointer-Dereference
    config->db_password = NULL;
    // ok: NULL-Pointer-Dereference
    config->db_connection = NULL;
    
    if (config_file == NULL) {
        free(config);
        return NULL;
    }
    
    FILE *f = fopen(config_file, "r");
    if (f == NULL) {
        free(config);
        return NULL;
    }
    // ok: NULL-Pointer-Dereference
    char line[MAX_BUFFER_SIZE];
    // ok: NULL-Pointer-Dereference
    while (fgets(line, sizeof(line), f)) {
        // ok: NULL-Pointer-Dereference
        if (strncmp(line, "host=", 5) == 0) {
            // ok: NULL-Pointer-Dereference
            config->db_host = strdup(line + 5);
        }
    }
    // ok: NULL-Pointer-Dereference
    fclose(f);
    return config;
}

void connect_database_vulnerable(DatabaseConfig *config) {
    // ruleid: NULL-Pointer-Dereference
    if (config->db_host == NULL) {
        return;
    }
    // ruleid: NULL-Pointer-Dereference
    printf("Connecting to %s:%d\n", config->db_host, config->db_port);
}

void connect_database_safe(DatabaseConfig *config) {
    if (config == NULL) {
        return;
    }
    // ok: NULL-Pointer-Dereference
    if (config->db_host == NULL) {
        return;
    }
    // ok: NULL-Pointer-Dereference
    printf("Connecting to %s:%d\n", config->db_host, config->db_port);
}

// ============================================================================
// SECTION 10: REAL-WORLD SCENARIO - EVENT HANDLER SYSTEM
// ============================================================================

int execute_handler_vulnerable(EventHandler *handler, void *data) {
    // ruleid: NULL-Pointer-Dereference
    if (handler->callback == NULL) {
        return -1;
    }
    // ruleid: NULL-Pointer-Dereference
    return handler->callback(data);
}

int execute_handler_safe(EventHandler *handler, void *data) {
    if (handler == NULL) {
        return -1;
    }
    // ok: NULL-Pointer-Dereference
    if (handler->callback == NULL) {
        return -1;
    }
    // ok: NULL-Pointer-Dereference
    return handler->callback(data);
}

void register_handler_vulnerable(EventHandler *handler, int (*cb)(void *), void *user_data) {
    // ruleid: NULL-Pointer-Dereference
    handler->callback = cb;
    // ruleid: NULL-Pointer-Dereference
    handler->user_data = user_data;
    // ruleid: NULL-Pointer-Dereference
    handler->description = strdup("Event handler");
}

void register_handler_safe(EventHandler *handler, int (*cb)(void *), void *user_data) {
    if (handler == NULL) {
        return;
    }
    // ok: NULL-Pointer-Dereference
    handler->callback = cb;
    // ok: NULL-Pointer-Dereference
    handler->user_data = user_data;
    // ok: NULL-Pointer-Dereference
    handler->description = strdup("Event handler");
}

// ============================================================================
// SECTION 11: C++ SPECIFIC PATTERNS
// ============================================================================

#ifdef __cplusplus

void test_cpp_shared_ptr_null() {
    std::shared_ptr<User> user;
    // ruleid: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_cpp_unique_ptr_null() {
    std::unique_ptr<Connection> conn;
    // ruleid: NULL-Pointer-Dereference
    int fd = conn->socket_fd;
    printf("Socket FD: %d\n", fd);
}

void test_cpp_shared_ptr_safe() {
    std::shared_ptr<User> user = std::make_shared<User>();
    if (user) {
        // ok: NULL-Pointer-Dereference
        int id = user->id;
        printf("User ID: %d\n", id);
    }
}

void test_cpp_unique_ptr_safe() {
    std::unique_ptr<Connection> conn = std::make_unique<Connection>();
    if (conn) {
        // ok: NULL-Pointer-Dereference
        int fd = conn->socket_fd;
        printf("Socket FD: %d\n", fd);
    }
}

void test_cpp_raw_ptr_null() {
    User *user = nullptr;
    // ruleid: NULL-Pointer-Dereference
    int id = user->id;
    printf("User ID: %d\n", id);
}

void test_cpp_raw_ptr_safe() {
    User *user = nullptr;
    if (user != nullptr) {
        // ok: NULL-Pointer-Dereference
        int id = user->id;
        printf("User ID: %d\n", id);
    }
}

#endif

// ============================================================================
// SECTION 12: EDGE CASES - CALLBACKS AND FUNCTION POINTERS
// ============================================================================

void execute_callback_vulnerable(void (*callback)(void *), void *data) {
    // ruleid: NULL-Pointer-Dereference
    callback(data);
}

void execute_callback_safe(void (*callback)(void *), void *data) {
    if (callback != NULL) {
        // ok: NULL-Pointer-Dereference
        callback(data);
    }
}

int process_with_callback_vulnerable(EventHandler *handler) {
    // ruleid: NULL-Pointer-Dereference
    return handler->callback(handler->user_data);
}

int process_with_callback_safe(EventHandler *handler) {
    if (handler != NULL && handler->callback != NULL) {
        // ok: NULL-Pointer-Dereference
        return handler->callback(handler->user_data);
    }
    return -1;
}

// ============================================================================
// SECTION 13: EDGE CASES - CHAINED DEREFERENCES
// ============================================================================

void test_chained_deref_vulnerable(User **users) {
    // ruleid: NULL-Pointer-Dereference
    int id = users[0]->id;
    printf("User ID: %d\n", id);
}

void test_chained_deref_safe(User **users) {
    if (users != NULL && users[0] != NULL) {
        // ok: NULL-Pointer-Dereference
        int id = users[0]->id;
        printf("User ID: %d\n", id);
    }
}

void test_nested_struct_vulnerable(DatabaseConfig *config) {
    // ruleid: NULL-Pointer-Dereference
    void *conn = config->db_connection;
    printf("Connection: %p\n", conn);
}

void test_nested_struct_safe(DatabaseConfig *config) {
    if (config != NULL) {
        // ok: NULL-Pointer-Dereference
        void *conn = config->db_connection;
        printf("Connection: %p\n", conn);
    }
}

// ============================================================================
// SECTION 14: EDGE CASES - RETURN VALUE CHECKS
// ============================================================================

User *get_user_by_id_vulnerable(UserDatabase *db, int id) {
    // ruleid: NULL-Pointer-Dereference
    for (int i = 0; i < db->count; i++) {
        // ruleid: NULL-Pointer-Dereference
        if (db->users[i]->id == id) {
            // ruleid: NULL-Pointer-Dereference
            return db->users[i];
        }
    }
    return NULL;
}

void use_returned_pointer_vulnerable(UserDatabase *db, int id) {
    // ruleid: NULL-Pointer-Dereference
    User *user = get_user_by_id_vulnerable(db, id);
    // ruleid: NULL-Pointer-Dereference
    printf("Name: %s\n", user->name);
}

void use_returned_pointer_safe(UserDatabase *db, int id) {
    // ok: NULL-Pointer-Dereference
    User *user = get_user_by_id_vulnerable(db, id);
    if (user != NULL) {
        // ok: NULL-Pointer-Dereference
        printf("Name: %s\n", user->name);
    }
}

// ============================================================================
// SECTION 15: EDGE CASES - MULTIPLE POINTERS
// ============================================================================

void test_multiple_pointers_vulnerable(User *user1, User *user2) {
    // ruleid: NULL-Pointer-Dereference
    int id1 = user1->id;
    // ruleid: NULL-Pointer-Dereference
    int id2 = user2->id;
    printf("IDs: %d, %d\n", id1, id2);
}

void test_multiple_pointers_safe(User *user1, User *user2) {
    if (user1 != NULL && user2 != NULL) {
        // ok: NULL-Pointer-Dereference
        int id1 = user1->id;
        // ok: NULL-Pointer-Dereference
        int id2 = user2->id;
        printf("IDs: %d, %d\n", id1, id2);
    }
}

// ============================================================================
// SECTION 16: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("NULL Pointer Dereference Test Suite\n");
    
    // Safe operations
    test_basic_null_safe_with_check();
    test_param_null_safe_with_check(NULL);
    test_malloc_with_check();
    
#ifdef __cplusplus
    test_cpp_shared_ptr_safe();
    test_cpp_unique_ptr_safe();
#endif
    
    // Create test resources
    UserDatabase *db = create_user_database(10);
    ConnectionPool *pool = create_pool(MAX_CONNECTIONS);
    
    // Clean up
    if (db) {
        for (int i = 0; i < db->count; i++) {
            free_user(db->users[i]);
        }
        free(db->users);
        free(db);
    }
    
    if (pool) {
        free(pool->connections);
        free(pool);
    }
    
    printf("Test compilation successful\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

#include <unistd.h>

static ssize_t send(int fd, const void *buf, size_t len, int flags) {
    return write(fd, buf, len);
}

static int close(int fd) {
    return 0;
}

static FILE *fopen(const char *pathname, const char *mode) {
    return NULL;
}

static int fclose(FILE *stream) {
    return 0;
}

static char *fgets(char *s, int size, FILE *stream) {
    return NULL;
}

static int strncmp(const char *s1, const char *s2, size_t n) {
    return 0;
}

static char *strdup(const char *s) {
    return NULL;
}