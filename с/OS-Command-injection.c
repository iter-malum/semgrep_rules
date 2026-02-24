// cmd_executor_test.c
// Realistic test suite for OS command injection detection
// Compile with: gcc -Wall -Wextra -std=c11 cmd_executor_test.c -o cmd_executor_test -ldl -lpthread
// C++ Compile: g++ -Wall -Wextra -std=c++17 cmd_executor_test.c -o cmd_executor_test -ldl -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <wchar.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __cplusplus
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <thread>
#include <QProcess>
#endif

// ============================================================================
// GLOBAL CONSTANTS AND MACROS
// ============================================================================

#define MAX_PATH_LEN 1024
#define MAX_CMD_LEN 2048
#define MAX_ARG_COUNT 64
#define MAX_ENV_VAR_LEN 512

static const char *const DEFAULT_CONFIG_PATH = "/etc/app_config";
static const char *const TRUSTED_COMMAND = "/usr/bin/safe_tool";
static const char *const SAFE_COMMAND_PREFIX = "/usr/bin/";
static const char *const ALLOWED_COMMANDS[] = {"ls", "grep", "cat", "echo", "date", "pwd", NULL};

const char *const GLOBAL_LOG_PATH = "/var/log/app.log";
static const char *g_default_shell = "/bin/sh";

// ============================================================================
// HELPER FUNCTIONS FOR SANITIZATION
// ============================================================================

static int is_allowed_command(const char *cmd) {
    for (int i = 0; ALLOWED_COMMANDS[i] != NULL; i++) {
        if (strncmp(cmd, ALLOWED_COMMANDS[i], strlen(ALLOWED_COMMANDS[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

static int contains_shell_metachar(const char *str) {
    const char *metachars = ";|&$`\\\"'<>(){}[]!#*?";
    for (int i = 0; metachars[i] != '\0'; i++) {
        if (strchr(str, metachars[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static void sanitize_command(char *cmd, size_t len) {
    for (size_t i = 0; i < len && cmd[i] != '\0'; i++) {
        if (contains_shell_metachar(&cmd[i])) {
            cmd[i] = '_';
        }
    }
}

static int validate_path(const char *path) {
    if (strstr(path, "..") != NULL) {
        return 0;
    }
    if (path[0] != '/') {
        return 0;
    }
    return 1;
}

// ============================================================================
// SECTION 1: SYSTEM() COMMAND EXECUTION
// ============================================================================

void run_user_command(const char *user_cmd) {
    // ruleid: OS-Command-Injection
    system(user_cmd);
}

void launch_process_from_args(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: OS-Command-Injection
    system(argv[1]);
}

void execute_env_command() {
    // ruleid: OS-Command-Injection
    system(getenv("USER_COMMAND"));
}

void build_and_run_command(const char *target) {
    char cmd[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    sprintf(cmd, "ls -la %s", target);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void build_and_run_with_strcat(const char *dir_name) {
    char cmd[MAX_CMD_LEN] = "cd ";
    // ruleid: OS-Command-Injection
    strcat(cmd, dir_name);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void build_and_run_with_strncat(const char *file_name) {
    char cmd[MAX_CMD_LEN] = "cat ";
    // ruleid: OS-Command-Injection
    strncat(cmd, file_name, MAX_PATH_LEN);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void run_trusted_command() {
    // ok: OS-Command-Injection
    system("ls -la");
}

void run_const_command() {
    // ok: OS-Command-Injection
    system(TRUSTED_COMMAND);
}

void run_sanitized_command(const char *user_input) {
    char cmd[MAX_CMD_LEN];
    if (contains_shell_metachar(user_input)) {
        fprintf(stderr, "Invalid characters in command\n");
        return;
    }
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    // ok: OS-Command-Injection (sanitized)
    system(cmd);
}

void run_allowlisted_command(const char *user_cmd) {
    if (!is_allowed_command(user_cmd)) {
        fprintf(stderr, "Command not in allowlist\n");
        return;
    }
    // ok: OS-Command-Injection (allowlisted)
    system(user_cmd);
}

// ============================================================================
// SECTION 2: POPEN() COMMAND EXECUTION
// ============================================================================

void fetch_file_contents(const char *filename) {
    char cmd[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    sprintf(cmd, "cat %s", filename);
    // ruleid: OS-Command-Injection
    FILE *f = popen(cmd, "r");
    if (f) {
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) {
            printf("%s", buf);
        }
        pclose(f);
    }
}

void process_user_data(const char *data) {
    // ruleid: OS-Command-Injection
    FILE *f = popen(data, "r");
    if (f) pclose(f);
}

void fetch_file_with_strcat(const char *dir, const char *file) {
    char cmd[MAX_CMD_LEN] = "cat ";
    // ruleid: OS-Command-Injection
    strcat(cmd, dir);
    // ruleid: OS-Command-Injection
    strcat(cmd, "/");
    // ruleid: OS-Command-Injection
    strcat(cmd, file);
    // ruleid: OS-Command-Injection
    FILE *f = popen(cmd, "r");
    if (f) pclose(f);
}

void safe_fetch_file(const char *filename) {
    // ok: OS-Command-Injection
    FILE *f = popen("ls -la", "r");
    if (f) pclose(f);
}

void safe_fetch_const_file(const char *filename) {
    // ok: OS-Command-Injection
    FILE *f = popen(TRUSTED_COMMAND, "r");
    if (f) pclose(f);
}

// ============================================================================
// SECTION 3: EXEC* FAMILY COMMAND EXECUTION
// ============================================================================

void launch_program(const char *path, char *const args[]) {
    // ruleid: OS-Command-Injection
    execv(path, args);
}

void launch_program_with_p(const char *file, char *const args[]) {
    // ruleid: OS-Command-Injection
    execvp(file, args);
}

void launch_program_with_env(const char *path, char *const arg0, char *const arg1, char *const envp[]) {
    // ruleid: OS-Command-Injection
    execle(path, arg0, arg1, NULL, envp);
}

void launch_program_with_va(const char *path, const char *arg, ...) {
    // This is a vulnerable implementation that doesn't handle varargs safely
    // ruleid: OS-Command-Injection
    execl(path, arg, NULL);
}

void safe_launch_program() {
    char *args[] = {"/bin/ls", "-la", NULL};
    // ok: OS-Command-Injection
    execv("/bin/ls", args);
}

void safe_launch_with_env() {
    char *envp[] = {"PATH=/usr/bin", NULL};
    // ok: OS-Command-Injection
    execle("/bin/ls", "ls", "-la", NULL, envp);
}

// ============================================================================
// SECTION 4: WINDOWS API COMMAND EXECUTION
// ============================================================================

#ifdef _WIN32

void create_process_from_input(const char *app_name, const char *cmd_line) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);
    
    // ruleid: OS-Command-Injection
    CreateProcessA(
        app_name,
        (LPSTR)cmd_line,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void execute_with_shell(const char *file, const char *params) {
    // ruleid: OS-Command-Injection
    ShellExecuteA(NULL, "open", file, params, NULL, SW_SHOWNORMAL);
}

void safe_create_process() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);
    
    // ok: OS-Command-Injection
    CreateProcessA(
        "notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void safe_execute_with_shell() {
    // ok: OS-Command-Injection
    ShellExecuteA(NULL, "open", "notepad.exe", NULL, NULL, SW_SHOWNORMAL);
}

#endif

// ============================================================================
// SECTION 5: DYNAMIC LIBRARY LOADING
// ============================================================================

void load_plugin(const char *plugin_name) {
    char path[MAX_PATH_LEN];
    // ruleid: OS-Command-Injection
    sprintf(path, "/usr/lib/plugins/%s.so", plugin_name);
    
#ifdef _WIN32
    // ruleid: OS-Command-Injection
    HMODULE h = LoadLibraryA(path);
    if (h) FreeLibrary(h);
#else
    // ruleid: OS-Command-Injection
    void *handle = dlopen(path, RTLD_LAZY);
    if (handle) dlclose(handle);
#endif
}

void load_trusted_plugin() {
    const char *plugin_path = "/usr/lib/plugins/trusted.so";
    
#ifdef _WIN32
    // ok: OS-Command-Injection
    HMODULE h = LoadLibraryA(plugin_path);
    if (h) FreeLibrary(h);
#else
    // ok: OS-Command-Injection
    void *handle = dlopen(plugin_path, RTLD_LAZY);
    if (handle) dlclose(handle);
#endif
}

// ============================================================================
// SECTION 6: C++ SPECIFIC COMMAND EXECUTION
// ============================================================================

#ifdef __cplusplus

void cpp_run_user_command(const std::string& cmd) {
    // ruleid: OS-Command-Injection
    std::system(cmd.c_str());
}

void cpp_run_from_args(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: OS-Command-Injection
    std::system(argv[1]);
}

void cpp_build_and_run(const std::string& filename) {
    // ruleid: OS-Command-Injection
    std::string cmd = "cat " + filename;
    // ruleid: OS-Command-Injection
    std::system(cmd.c_str());
}

void cpp_build_and_run_with_format(const std::string& dir, const std::string& file) {
    // ruleid: OS-Command-Injection
    std::string cmd = "ls " + dir + "/" + file;
    // ruleid: OS-Command-Injection
    std::system(cmd.c_str());
}

void cpp_safe_run() {
    // ok: OS-Command-Injection
    std::system("ls -la");
}

void cpp_safe_run_const() {
    // ok: OS-Command-Injection
    std::system(TRUSTED_COMMAND);
}

void cpp_safe_run_sanitized(const std::string& input) {
    if (contains_shell_metachar(input.c_str())) {
        return;
    }
    std::string cmd = "echo " + input;
    // ok: OS-Command-Injection (sanitized)
    std::system(cmd.c_str());
}

void qt_run_command(const QString& command) {
    QProcess process;
    // ruleid: OS-Command-Injection
    process.start(command);
    process.waitForFinished();
}

void qt_run_with_args(const QString& program, const QStringList& args) {
    QProcess process;
    // ruleid: OS-Command-Injection
    process.start(program, args);
    process.waitForFinished();
}

void qt_safe_run() {
    QProcess process;
    // ok: OS-Command-Injection
    process.start("ls", QStringList() << "-la");
    process.waitForFinished();
}

#endif

// ============================================================================
// SECTION 7: REAL-WORLD SCENARIO - WEB SERVER REQUEST HANDLER
// ============================================================================

typedef struct {
    char *method;
    char *path;
    char *query_string;
    char *headers;
    char *body;
} HttpRequest;

typedef struct {
    int status;
    char *content_type;
    char *body;
} HttpResponse;

HttpResponse *handle_file_request(const char *base_dir, const char *requested_path) {
    char full_path[MAX_PATH_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(full_path, sizeof(full_path), "%s%s", base_dir, requested_path);
    
    // ruleid: OS-Command-Injection
    FILE *f = popen(full_path, "r");
    if (!f) {
        return NULL;
    }
    
    HttpResponse *resp = (HttpResponse *)malloc(sizeof(HttpResponse));
    resp->status = 200;
    resp->content_type = "text/html";
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    resp->body = (char *)malloc(size + 1);
    fread(resp->body, 1, size, f);
    resp->body[size] = '\0';
    
    pclose(f);
    return resp;
}

HttpResponse *handle_file_request_safe(const char *base_dir, const char *requested_path) {
    if (strstr(requested_path, "..") != NULL) {
        fprintf(stderr, "Path traversal attempt detected\n");
        return NULL;
    }
    
    if (requested_path[0] == '/') {
        requested_path++;
    }
    
    char full_path[MAX_PATH_LEN];
    snprintf(full_path, sizeof(full_path), "%s/%s", base_dir, requested_path);
    
    // ok: OS-Command-Injection (sanitized)
    FILE *f = popen(full_path, "r");
    if (!f) {
        return NULL;
    }
    
    HttpResponse *resp = (HttpResponse *)malloc(sizeof(HttpResponse));
    resp->status = 200;
    pclose(f);
    return resp;
}

// ============================================================================
// SECTION 8: REAL-WORLD SCENARIO - CONFIG LOADER
// ============================================================================

typedef struct {
    char config_path[MAX_PATH_LEN];
    char log_path[MAX_PATH_LEN];
    char shell_cmd[MAX_PATH_LEN];
    int debug_mode;
} AppConfig;

int load_config(AppConfig *config, const char *config_file) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "cat %s", config_file);
    // ruleid: OS-Command-Injection
    FILE *f = popen(cmd, "r");
    
    if (!f) return -1;
    
    // ruleid: OS-Command-Injection
    fgets(config->config_path, sizeof(config->config_path), f);
    // ruleid: OS-Command-Injection
    fgets(config->log_path, sizeof(config->log_path), f);
    // ruleid: OS-Command-Injection
    fgets(config->shell_cmd, sizeof(config->shell_cmd), f);
    
    pclose(f);
    
    // ruleid: OS-Command-Injection
    setenv("APP_CONFIG", config->config_path, 1);
    // ruleid: OS-Command-Injection
    setenv("LOG_PATH", config->log_path, 1);
    
    return 0;
}

int load_config_safe(AppConfig *config, const char *config_file) {
    if (strstr(config_file, "..") != NULL) {
        fprintf(stderr, "Invalid config file path\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "cat %s", config_file);
    
    // ok: OS-Command-Injection (sanitized)
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    
    fgets(config->config_path, sizeof(config->config_path), f);
    fgets(config->log_path, sizeof(config->log_path), f);
    fgets(config->shell_cmd, sizeof(config->shell_cmd), f);
    
    pclose(f);
    
    // ok: OS-Command-Injection (sanitized)
    setenv("APP_CONFIG", config->config_path, 1);
    setenv("LOG_PATH", config->log_path, 1);
    
    return 0;
}

// ============================================================================
// SECTION 9: REAL-WORLD SCENARIO - USER SHELL EXECUTOR
// ============================================================================

typedef struct {
    char *username;
    char *home_dir;
    int permissions;
} UserContext;

int execute_user_shell(UserContext *ctx, const char *command) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "sudo -u %s %s", ctx->username, command);
    // ruleid: OS-Command-Injection
    int ret = system(cmd);
    return ret;
}

int execute_user_shell_safe(UserContext *ctx, const char *command) {
    if (contains_shell_metachar(command)) {
        fprintf(stderr, "Invalid command\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "sudo -u %s %s", ctx->username, command);
    
    // ok: OS-Command-Injection (sanitized)
    int ret = system(cmd);
    return ret;
}

// ============================================================================
// SECTION 10: REAL-WORLD SCENARIO - LOG ROTATION
// ============================================================================

void rotate_log_file(const char *log_path) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "gzip %s && mv %s.gz %s.old", log_path, log_path, log_path);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void rotate_log_file_safe(const char *log_path) {
    if (!validate_path(log_path)) {
        fprintf(stderr, "Invalid log path\n");
        return;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "gzip %s && mv %s.gz %s.old", log_path, log_path, log_path);
    
    // ok: OS-Command-Injection (path validated)
    system(cmd);
}

// ============================================================================
// SECTION 11: EDGE CASES - MACROS AND CONSTANTS
// ============================================================================

void macro_based_command(const char *extra_args) {
    char cmd[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "%s %s", TRUSTED_COMMAND, extra_args);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void const_path_vulnerability(const char *lib_suffix) {
    char path[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    snprintf(path, sizeof(path), "%s%s", SAFE_COMMAND_PREFIX, lib_suffix);
    
#ifdef _WIN32
    // ruleid: OS-Command-Injection
    HMODULE h = LoadLibraryA(path);
    if (h) FreeLibrary(h);
#else
    // ruleid: OS-Command-Injection
    void *handle = dlopen(path, RTLD_LAZY);
    if (handle) dlclose(handle);
#endif
}

void global_shell_vulnerability(const char *script_name) {
    char cmd[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "%s %s", g_default_shell, script_name);
    // ruleid: OS-Command-Injection
    system(cmd);
}

// ============================================================================
// SECTION 12: EDGE CASES - MULTIPLE INPUT SOURCES
// ============================================================================

void multiple_sources_vulnerability(int argc, char *argv[], const char *user_input) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "%s %s %s", argv[1], getenv("EXTRA_ARGS"), user_input);
    // ruleid: OS-Command-Injection
    system(cmd);
}

void nested_function_vulnerability(const char *input) {
    char cmd[MAX_CMD_LEN];
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), "echo %s", input);
    // ruleid: OS-Command-Injection
    system(strcpy(cmd, cmd));
}

// ============================================================================
// SECTION 13: EDGE CASES - WIDE CHARACTER FUNCTIONS
// ============================================================================

void wsystem_vulnerability(const wchar_t *wcmd) {
    // ruleid: OS-Command-Injection
    _wsystem(wcmd);
}

void wpopen_vulnerability(const wchar_t *wcmd) {
    // ruleid: OS-Command-Injection
    FILE *f = _wpopen(wcmd, L"r");
    if (f) pclose(f);
}

void wsystem_safe_literal() {
    // ok: OS-Command-Injection
    _wsystem(L"dir");
}

// ============================================================================
// SECTION 14: EDGE CASES - FUNCTION POINTERS AND CALLBACKS
// ============================================================================

typedef int (*CommandExecutor)(const char *cmd);

int execute_with_callback(CommandExecutor exec, const char *user_cmd) {
    // ruleid: OS-Command-Injection
    return exec(user_cmd);
}

int execute_with_callback_safe(CommandExecutor exec, const char *cmd) {
    if (!is_allowed_command(cmd)) {
        return -1;
    }
    // ok: OS-Command-Injection (validated)
    return exec(cmd);
}

// ============================================================================
// SECTION 15: EDGE CASES - ENVIRONMENT INHERITANCE
// ============================================================================

void inherit_environment_vulnerability(const char *new_path) {
    // ruleid: OS-Command-Injection
    setenv("PATH", new_path, 1);
    // ruleid: OS-Command-Injection
    setenv("LD_LIBRARY_PATH", new_path, 1);
    // ruleid: OS-Command-Injection
    system("some_command");
}

void clean_environment_safe() {
    // ok: OS-Command-Injection
    setenv("PATH", "/usr/bin:/bin", 1);
    // ok: OS-Command-Injection
    setenv("LD_LIBRARY_PATH", "/usr/lib", 1);
    // ok: OS-Command-Injection
    system("ls -la");
}

// ============================================================================
// SECTION 16: REAL-WORLD SCENARIO - BACKUP SYSTEM
// ============================================================================

typedef struct {
    char *backup_dir;
    char *source_dir;
    int retention_days;
    int compression_level;
} BackupConfig;

int perform_backup(BackupConfig *config) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd), 
             "rsync -avz --delete %s/ %s/ && "
             "find %s -type f -mtime +%d -delete",
             config->source_dir, 
             config->backup_dir,
             config->backup_dir,
             config->retention_days);
    
    // ruleid: OS-Command-Injection
    return system(cmd);
}

int perform_backup_safe(BackupConfig *config) {
    if (!validate_path(config->source_dir) || !validate_path(config->backup_dir)) {
        fprintf(stderr, "Invalid path in backup configuration\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), 
             "rsync -avz --delete %s/ %s/ && "
             "find %s -type f -mtime +%d -delete",
             config->source_dir, 
             config->backup_dir,
             config->backup_dir,
             config->retention_days);
    
    // ok: OS-Command-Injection (paths validated)
    return system(cmd);
}

// ============================================================================
// SECTION 17: REAL-WORLD SCENARIO - IMAGE PROCESSING
// ============================================================================

typedef struct {
    char input_file[MAX_PATH_LEN];
    char output_file[MAX_PATH_LEN];
    int width;
    int height;
    char format[10];
} ImageProcessingConfig;

int process_image(ImageProcessingConfig *config) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd),
             "convert %s -resize %dx%d %s:%s",
             config->input_file,
             config->width,
             config->height,
             config->format,
             config->output_file);
    
    // ruleid: OS-Command-Injection
    return system(cmd);
}

int process_image_safe(ImageProcessingConfig *config) {
    if (!validate_path(config->input_file) || !validate_path(config->output_file)) {
        fprintf(stderr, "Invalid path in image processing\n");
        return -1;
    }
    
    // Validate format to prevent command injection
    if (strcmp(config->format, "png") != 0 && 
        strcmp(config->format, "jpg") != 0 && 
        strcmp(config->format, "jpeg") != 0) {
        fprintf(stderr, "Invalid image format\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
             "convert %s -resize %dx%d %s:%s",
             config->input_file,
             config->width,
             config->height,
             config->format,
             config->output_file);
    
    // ok: OS-Command-Injection (paths and format validated)
    return system(cmd);
}

// ============================================================================
// SECTION 18: REAL-WORLD SCENARIO - NETWORK MONITORING
// ============================================================================

typedef struct {
    char target_host[MAX_PATH_LEN];
    int port;
    int timeout;
    char protocol[10];
} NetworkMonitorConfig;

int monitor_network(NetworkMonitorConfig *config) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd),
             "nmap -p %d -s%s -T4 -oG - %s | grep 'open'",
             config->port,
             config->protocol,
             config->target_host);
    
    // ruleid: OS-Command-Injection
    return system(cmd);
}

int monitor_network_safe(NetworkMonitorConfig *config) {
    // Validate host to prevent command injection
    if (contains_shell_metachar(config->target_host)) {
        fprintf(stderr, "Invalid target host\n");
        return -1;
    }
    
    // Validate protocol
    if (strcmp(config->protocol, "T") != 0 && 
        strcmp(config->protocol, "U") != 0) {
        fprintf(stderr, "Invalid protocol\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
             "nmap -p %d -s%s -T4 -oG - %s | grep 'open'",
             config->port,
             config->protocol,
             config->target_host);
    
    // ok: OS-Command-Injection (input validated)
    return system(cmd);
}

// ============================================================================
// SECTION 19: REAL-WORLD SCENARIO - REPORT GENERATOR
// ============================================================================

typedef struct {
    char output_format[10];
    char report_name[MAX_PATH_LEN];
    char template_path[MAX_PATH_LEN];
    char data_source[MAX_PATH_LEN];
} ReportConfig;

int generate_report(ReportConfig *config) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: OS-Command-Injection
    snprintf(cmd, sizeof(cmd),
             "reportgen --format %s --name %s --template %s --source %s",
             config->output_format,
             config->report_name,
             config->template_path,
             config->data_source);
    
    // ruleid: OS-Command-Injection
    return system(cmd);
}

int generate_report_safe(ReportConfig *config) {
    // Validate output format
    if (strcmp(config->output_format, "pdf") != 0 && 
        strcmp(config->output_format, "html") != 0 &&
        strcmp(config->output_format, "csv") != 0) {
        fprintf(stderr, "Invalid output format\n");
        return -1;
    }
    
    if (!validate_path(config->template_path) || !validate_path(config->data_source)) {
        fprintf(stderr, "Invalid path in report configuration\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd),
             "reportgen --format %s --name %s --template %s --source %s",
             config->output_format,
             config->report_name,
             config->template_path,
             config->data_source);
    
    // ok: OS-Command-Injection (input validated)
    return system(cmd);
}

// ============================================================================
// SECTION 20: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("OS Command Injection Test Suite\n");
    
    // Safe operations
    run_trusted_command();
    run_const_command();
    safe_fetch_file("test.txt");
    safe_fetch_const_file("test.txt");
    
#ifdef _WIN32
    safe_create_process();
    safe_execute_with_shell();
#endif

#ifdef __cplusplus
    cpp_safe_run();
    cpp_safe_run_const();
    qt_safe_run();
#endif
    
    // Run some test operations with user input if provided
    if (argc > 1) {
        printf("Running tests with user input: %s\n", argv[1]);
        
        // These would be vulnerable in real usage
        run_user_command(argv[1]);
        launch_process_from_args(argc, argv);
        build_and_run_command(argv[1]);
        build_and_run_with_strcat(argv[1]);
        
#ifdef __cplusplus
        cpp_run_user_command(argv[1]);
        cpp_build_and_run(argv[1]);
#endif
    }
    
    printf("Test compilation successful\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

#include <time.h>

static time_t time(time_t *arg) {
    return 1234567890;
}

static int strcmp(const char *s1, const char *s2) {
    return 0;
}

static char *strdup(const char *s) {
    return (char *)s;
}