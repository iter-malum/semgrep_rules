// test_path_traversal.c
// Comprehensive test suite for CWE-23: Relative Path Traversal detection
// Compile with: gcc -Wall -Wextra -std=c11 test_path_traversal.c -o test_path
// C++ Compile: g++ -Wall -Wextra -std=c++17 test_path_traversal.c -o test_path

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <wchar.h>
#include <locale.h>

#ifdef __cplusplus
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
namespace fs = std::filesystem;
#endif

// ============================================================================
// GLOBAL CONSTANTS AND MACROS
// ============================================================================

#define CONFIG_DIR "/etc/myapp"
#define DATA_DIR "/var/data"
#define MAX_PATH 512
#define TRUSTED_FILE "trusted_config.txt"

const char *const TRUSTED_PATH = "/usr/share/myapp/data";
static const char *g_base_dir = "/var/log";

// ============================================================================
// HELPER FUNCTIONS FOR SANITIZATION
// ============================================================================

static int contains_parent_dir(const char *path) {
    return (strstr(path, "..") != NULL);
}

static int is_absolute_path(const char *path) {
    return (path[0] == '/' || path[0] == '\\');
}

static void sanitize_path(char *path, size_t len) {
    char *p = path;
    while ((p = strstr(p, "..")) != NULL) {
        memmove(p, p + 2, strlen(p + 2) + 1);
    }
}

// ============================================================================
// SECTION 1: FOPEN - BASIC FILE OPERATIONS
// ============================================================================

void test_fopen_vulnerable_user_input(char *user_filename) {
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(user_filename, "r");
    if (f) fclose(f);
}

void test_fopen_vulnerable_argv(int argc, char *argv[]) {
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(argv[1], "r");
    if (f) fclose(f);
}

void test_fopen_vulnerable_getenv() {
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(getenv("CONFIG_FILE"), "r");
    if (f) fclose(f);
}

void test_fopen_vulnerable_concat(char *filename) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "/var/data/%s", filename);
    // ruleid: Relative-Path-Traversal
    fopen(path, "r");
}

void test_fopen_vulnerable_strcat(char *subdir, char *filename) {
    char path[MAX_PATH] = "/var/data/";
    // ruleid: Relative-Path-Traversal
    strcat(path, subdir);
    // ruleid: Relative-Path-Traversal
    strcat(path, "/");
    // ruleid: Relative-Path-Traversal
    strcat(path, filename);
    // ruleid: Relative-Path-Traversal
    fopen(path, "r");
}

void test_fopen_safe_literal() {
    // ok: Relative-Path-Traversal
    FILE *f = fopen("config.txt", "r");
    if (f) fclose(f);
}

void test_fopen_safe_const() {
    // ok: Relative-Path-Traversal
    FILE *f = fopen(TRUSTED_FILE, "r");
    if (f) fclose(f);
}

void test_fopen_safe_sanitized(char *filename) {
    if (contains_parent_dir(filename)) {
        fprintf(stderr, "Invalid path\n");
        return;
    }
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/var/data/%s", filename);
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void test_fopen_safe_absolute_check(char *filename) {
    if (!is_absolute_path(filename)) {
        fprintf(stderr, "Must be absolute path\n");
        return;
    }
    // ok: Relative-Path-Traversal (validated)
    FILE *f = fopen(filename, "r");
    if (f) fclose(f);
}

// ============================================================================
// SECTION 2: OPEN/CREAT - POSIX FILE OPERATIONS
// ============================================================================

void test_open_vulnerable(char *path) {
    // ruleid: Relative-Path-Traversal
    int fd = open(path, O_RDONLY);
    if (fd >= 0) close(fd);
}

void test_open_vulnerable_flags(char *filename, int flags) {
    // ruleid: Relative-Path-Traversal
    int fd = open(filename, flags, 0644);
    if (fd >= 0) close(fd);
}

void test_creat_vulnerable(char *filename) {
    // ruleid: Relative-Path-Traversal
    int fd = creat(filename, 0644);
    if (fd >= 0) close(fd);
}

void test_open_safe_literal() {
    // ok: Relative-Path-Traversal
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) close(fd);
}

void test_open_safe_const() {
    // ok: Relative-Path-Traversal
    int fd = open(CONFIG_DIR "/settings.conf", O_RDONLY);
    if (fd >= 0) close(fd);
}

// ============================================================================
// SECTION 3: REMOVE/DELETE - FILE DELETION
// ============================================================================

void test_remove_vulnerable(char *filename) {
    // ruleid: Relative-Path-Traversal
    remove(filename);
}

void test_remove_vulnerable_user_dir(char *user_dir, char *filename) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/%s", user_dir, filename);
    // ruleid: Relative-Path-Traversal
    remove(path);
}

void test_remove_safe_literal() {
    // ok: Relative-Path-Traversal
    remove("/tmp/old_temp_file.txt");
}

void test_remove_safe_temp_file() {
    char *temp_file = "/tmp/cleanup_me.txt";
    // ok: Relative-Path-Traversal
    remove(temp_file);
}

// ============================================================================
// SECTION 4: STAT/ACCESS - FILE METADATA OPERATIONS
// ============================================================================

void test_stat_vulnerable(char *path) {
    struct stat st;
    // ruleid: Relative-Path-Traversal
    stat(path, &st);
}

void test_lstat_vulnerable_symlink(char *link_path) {
    struct stat st;
    // ruleid: Relative-Path-Traversal
    lstat(link_path, &st);
}

void test_access_vulnerable(char *filepath) {
    // ruleid: Relative-Path-Traversal
    if (access(filepath, R_OK) == 0) {
        printf("File is readable\n");
    }
}

void test_stat_safe_literal() {
    struct stat st;
    // ok: Relative-Path-Traversal
    stat("/etc/hosts", &st);
}

void test_access_safe_const() {
    // ok: Relative-Path-Traversal
    if (access(TRUSTED_PATH, R_OK) == 0) {
        printf("Trusted path exists\n");
    }
}

// ============================================================================
// SECTION 5: CHDIR - DIRECTORY CHANGE OPERATIONS
// ============================================================================

void test_chdir_vulnerable(char *directory) {
    // ruleid: Relative-Path-Traversal
    chdir(directory);
}

void test_chdir_vulnerable_user_home(char *username) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "/home/%s", username);
    // ruleid: Relative-Path-Traversal
    chdir(path);
}

void test_chdir_safe_literal() {
    // ok: Relative-Path-Traversal
    chdir("/var/www");
}

void test_chdir_safe_const() {
    // ok: Relative-Path-Traversal
    chdir(DATA_DIR);
}

// ============================================================================
// SECTION 6: RENAME - FILE RENAME OPERATIONS
// ============================================================================

void test_rename_vulnerable(char *old_name, char *new_name) {
    // ruleid: Relative-Path-Traversal
    rename(old_name, new_name);
}

void test_rename_vulnerable_partial(char *new_name) {
    // ruleid: Relative-Path-Traversal
    rename("/tmp/old_file", new_name);
}

void test_rename_safe_literal() {
    // ok: Relative-Path-Traversal
    rename("/tmp/old.txt", "/tmp/new.txt");
}

// ============================================================================
// SECTION 7: SPRINTF/SNPRINTF - PATH CONSTRUCTION
// ============================================================================

void test_sprintf_vulnerable_path(char *user_input) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "/var/data/%s", user_input);
}

void test_sprintf_vulnerable_multiple(char *dir, char *file) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/%s", dir, file);
}

void test_snprintf_vulnerable(char *filename) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    snprintf(path, sizeof(path), "/var/log/%s.log", filename);
}

void test_sprintf_safe_literal() {
    char path[MAX_PATH];
    // ok: Relative-Path-Traversal
    sprintf(path, "/var/data/%s", "fixed_filename");
}

void test_snprintf_safe_const() {
    char path[MAX_PATH];
    // ok: Relative-Path-Traversal
    snprintf(path, sizeof(path), "%s/config", CONFIG_DIR);
}

// ============================================================================
// SECTION 8: WIDE CHARACTER FUNCTIONS
// ============================================================================

void test_wfopen_vulnerable(wchar_t *wpath) {
    // ruleid: Relative-Path-Traversal
    FILE *f = _wfopen(wpath, L"r");
    if (f) fclose(f);
}

void test_wopen_vulnerable(wchar_t *wpath) {
    // ruleid: Relative-Path-Traversal
    int fd = _wopen(wpath, _O_RDONLY);
    if (fd >= 0) _close(fd);
}

void test_wstat_vulnerable(wchar_t *wpath) {
    struct _stat st;
    // ruleid: Relative-Path-Traversal
    _wstat(wpath, &st);
}

void test_wfopen_safe_literal() {
    // ok: Relative-Path-Traversal
    FILE *f = _wfopen(L"config.txt", L"r");
    if (f) fclose(f);
}

// ============================================================================
// SECTION 9: REAL-WORLD SCENARIOS - WEB SERVER
// ============================================================================

typedef struct {
    char *method;
    char *path;
    char *headers;
    char *body;
} HTTPRequest;

typedef struct {
    int status;
    char *content_type;
    char *body;
} HTTPResponse;

static HTTPResponse *serve_file(const char *base_dir, const char *requested_path) {
    char full_path[MAX_PATH];
    
    // ruleid: Relative-Path-Traversal
    sprintf(full_path, "%s%s", base_dir, requested_path);
    
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(full_path, "rb");
    if (!f) {
        return NULL;
    }
    
    HTTPResponse *resp = malloc(sizeof(HTTPResponse));
    resp->status = 200;
    resp->content_type = "text/html";
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    resp->body = malloc(size + 1);
    fread(resp->body, 1, size, f);
    resp->body[size] = '\0';
    
    fclose(f);
    return resp;
}

static HTTPResponse *serve_file_safe(const char *base_dir, const char *requested_path) {
    if (strstr(requested_path, "..") != NULL) {
        fprintf(stderr, "Path traversal attempt detected\n");
        return NULL;
    }
    
    if (requested_path[0] == '/') {
        requested_path++;
    }
    
    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, requested_path);
    
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(full_path, "rb");
    if (!f) {
        return NULL;
    }
    
    HTTPResponse *resp = malloc(sizeof(HTTPResponse));
    resp->status = 200;
    fclose(f);
    return resp;
}

// ============================================================================
// SECTION 10: REAL-WORLD SCENARIOS - CONFIG LOADER
// ============================================================================

typedef struct {
    char config_path[MAX_PATH];
    char log_path[MAX_PATH];
    int debug_mode;
} AppConfig;

static int load_config(AppConfig *config, char *config_dir) {
    char path[MAX_PATH];
    
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/app.conf", config_dir);
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "r");
    
    if (!f) {
        // ruleid: Relative-Path-Traversal
        sprintf(path, "%s/../defaults/app.conf", config_dir);
        // ruleid: Relative-Path-Traversal
        f = fopen(path, "r");
    }
    
    if (f) {
        fclose(f);
        return 0;
    }
    return -1;
}

static int load_config_safe(AppConfig *config, const char *config_dir) {
    if (strstr(config_dir, "..") != NULL) {
        fprintf(stderr, "Invalid config directory\n");
        return -1;
    }
    
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/app.conf", config_dir);
    
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return 0;
    }
    return -1;
}

// ============================================================================
// SECTION 11: REAL-WORLD SCENARIOS - FILE MANAGER
// ============================================================================

typedef struct {
    char *username;
    char *home_dir;
    int permissions;
} UserContext;

static int save_user_file(UserContext *ctx, char *filename, char *data) {
    char path[MAX_PATH];
    
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/documents/%s", ctx->home_dir, filename);
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "w");
    
    if (f) {
        fprintf(f, "%s", data);
        fclose(f);
        return 0;
    }
    return -1;
}

static int delete_user_file(UserContext *ctx, char *filename) {
    char path[MAX_PATH];
    
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/documents/%s", ctx->home_dir, filename);
    // ruleid: Relative-Path-Traversal
    remove(path);
    
    return 0;
}

static int save_user_file_safe(UserContext *ctx, const char *filename, char *data) {
    if (strstr(filename, "..") != NULL) {
        fprintf(stderr, "Invalid filename\n");
        return -1;
    }
    
    if (filename[0] == '/') {
        fprintf(stderr, "Absolute paths not allowed\n");
        return -1;
    }
    
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/documents/%s", ctx->home_dir, filename);
    
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s", data);
        fclose(f);
        return 0;
    }
    return -1;
}

// ============================================================================
// SECTION 12: REAL-WORLD SCENARIOS - LOG WRITER
// ============================================================================

static void write_log_entry(char *log_dir, char *filename, char *message) {
    char path[MAX_PATH];
    
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/%s", log_dir, filename);
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "a");
    
    if (f) {
        fprintf(f, "[%ld] %s\n", time(NULL), message);
        fclose(f);
    }
}

static void write_log_entry_safe(const char *log_dir, const char *filename, char *message) {
    if (strstr(filename, "..") != NULL) {
        return;
    }
    
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/%s", log_dir, filename);
    
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(path, "a");
    if (f) {
        fprintf(f, "[%ld] %s\n", time(NULL), message);
        fclose(f);
    }
}

// ============================================================================
// SECTION 13: C++ SPECIFIC - STD::IFSTREAM/OFSTREAM
// ============================================================================

#ifdef __cplusplus

void test_cpp_ifstream_vulnerable(const std::string& path) {
    // ruleid: Relative-Path-Traversal
    std::ifstream file(path);
}

void test_cpp_ofstream_vulnerable(std::string filename) {
    // ruleid: Relative-Path-Traversal
    std::ofstream out(filename);
}

void test_cpp_fstream_vulnerable(char *path) {
    // ruleid: Relative-Path-Traversal
    std::fstream fs(path, std::ios::in | std::ios::out);
}

void test_cpp_ifstream_safe() {
    // ok: Relative-Path-Traversal
    std::ifstream file("config.txt");
}

void test_cpp_ofstream_safe() {
    // ok: Relative-Path-Traversal
    std::ofstream out("/var/log/app.log");
}

void test_cpp_fstream_safe() {
    // ok: Relative-Path-Traversal
    std::fstream fs(TRUSTED_FILE, std::ios::in);
}

// ============================================================================
// SECTION 14: C++ SPECIFIC - STD::FILESYSTEM
// ============================================================================

void test_cpp_fs_exists_vulnerable(const std::string& path) {
    // ruleid: Relative-Path-Traversal
    if (fs::exists(path)) {
        std::cout << "File exists\n";
    }
}

void test_cpp_fs_remove_vulnerable(char *filepath) {
    // ruleid: Relative-Path-Traversal
    fs::remove(filepath);
}

void test_cpp_fs_rename_vulnerable(const std::string& old_path, const std::string& new_path) {
    // ruleid: Relative-Path-Traversal
    fs::rename(old_path, new_path);
}

void test_cpp_fs_copy_vulnerable(std::string src, std::string dst) {
    // ruleid: Relative-Path-Traversal
    fs::copy_file(src, dst);
}

void test_cpp_fs_exists_safe() {
    // ok: Relative-Path-Traversal
    if (fs::exists("/etc/hosts")) {
        std::cout << "Hosts file exists\n";
    }
}

void test_cpp_fs_remove_safe() {
    // ok: Relative-Path-Traversal
    fs::remove("/tmp/temp_file.txt");
}

// ============================================================================
// SECTION 15: C++ SPECIFIC - PATH CONCATENATION
// ============================================================================

void test_cpp_path_concat_vulnerable(const std::string& base_dir, const std::string& filename) {
    // ruleid: Relative-Path-Traversal
    std::string full_path = base_dir + "/" + filename;
    // ruleid: Relative-Path-Traversal
    std::ifstream file(full_path);
}

void test_cpp_path_concat_safe(const std::string& base_dir, const std::string& filename) {
    if (filename.find("..") != std::string::npos) {
        return;
    }
    
    std::string full_path = base_dir + "/" + filename;
    // ok: Relative-Path-Traversal (sanitized)
    std::ifstream file(full_path);
}

#endif

// ============================================================================
// SECTION 16: EDGE CASES - MACROS AND CONST
// ============================================================================

void test_macro_path_vulnerable(char *subdir) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/%s", DATA_DIR, subdir);
    // ruleid: Relative-Path-Traversal
    fopen(path, "r");
}

void test_const_path_vulnerable(char *filename) {
    // ruleid: Relative-Path-Traversal
    fopen(TRUSTED_PATH, "r");
}

void test_global_dir_vulnerable(char *filename) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s/%s", g_base_dir, filename);
    // ruleid: Relative-Path-Traversal
    fopen(path, "a");
}

// ============================================================================
// SECTION 17: EDGE CASES - MULTIPLE LEVELS
// ============================================================================

void test_nested_path_vulnerable(char *level1, char *level2, char *filename) {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "/var/data/%s/%s/%s", level1, level2, filename);
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void test_nested_path_safe(const char *level1, const char *level2, const char *filename) {
    if (strstr(level1, "..") || strstr(level2, "..") || strstr(filename, "..")) {
        return;
    }
    
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/var/data/%s/%s/%s", level1, level2, filename);
    
    // ok: Relative-Path-Traversal (sanitized)
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

// ============================================================================
// SECTION 18: EDGE CASES - USER INPUT SOURCES
// ============================================================================

void test_argv_vulnerable(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(argv[1], "r");
    if (f) fclose(f);
}

void test_getenv_vulnerable() {
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(getenv("HOME"), "r");
    if (f) fclose(f);
}

void test_fgets_vulnerable() {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    fgets(path, sizeof(path), stdin);
    path[strcspn(path, "\n")] = 0;
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

void test_scanf_vulnerable() {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    scanf("%s", path);
    // ruleid: Relative-Path-Traversal
    FILE *f = fopen(path, "r");
    if (f) fclose(f);
}

// ============================================================================
// SECTION 19: EDGE CASES - FUNCTION RETURNS
// ============================================================================

static char *get_config_path(char *user_input) {
    static char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "/etc/myapp/%s", user_input);
    return path;
}

static void use_config_path() {
    char path[MAX_PATH];
    // ruleid: Relative-Path-Traversal
    sprintf(path, "%s", get_config_path("config"));
    // ruleid: Relative-Path-Traversal
    fopen(path, "r");
}

// ============================================================================
// SECTION 20: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Path Traversal Test Suite\n");
    
    // Safe operations
    test_fopen_safe_literal();
    test_open_safe_literal();
    test_remove_safe_literal();
    
#ifdef __cplusplus
    test_cpp_ifstream_safe();
    test_cpp_ofstream_safe();
    test_cpp_fs_exists_safe();
#endif
    
    if (argc > 1) {
        // These would be vulnerable in real usage
        printf("Argument provided: %s\n", argv[1]);
    }
    
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

#include <time.h>

static time_t time(time_t *arg) {
    return 1234567890;
}