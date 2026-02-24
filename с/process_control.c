// test_process_control.c
// Comprehensive test suite for CWE-114: Process Control detection
// Compile with: gcc -Wall -Wextra -std=c11 test_process_control.c -o test_process
// C++ Compile: g++ -Wall -Wextra -std=c++17 test_process_control.c -o test_process -ldl

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <wchar.h>
#include <locale.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __cplusplus
#include <cstdlib>
#include <string>
#include <QProcess>
namespace fs = std::filesystem;
#endif

// ============================================================================
// GLOBAL CONSTANTS AND MACROS
// ============================================================================

#define SYSTEM_LIB "libsystem.so"
#define TRUSTED_CMD "ls -la"
#define SAFE_LIBRARY "kernel32.dll"
#define MAX_CMD_LEN 1024
#define PLUGIN_DIR "/usr/lib/plugins"

const char *const TRUSTED_COMMAND = "/bin/echo hello";
const char *const SAFE_LIB_PATH = "/usr/lib/safe_library.so";
static const char *g_default_shell = "/bin/sh";

// ============================================================================
// HELPER FUNCTIONS FOR SANITIZATION
// ============================================================================

static int is_safe_command(const char *cmd) {
    const char *safe_cmds[] = {"ls", "echo", "date", "pwd", NULL};
    for (int i = 0; safe_cmds[i] != NULL; i++) {
        if (strncmp(cmd, safe_cmds[i], strlen(safe_cmds[i])) == 0) {
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

// ============================================================================
// SECTION 1: system() - COMMAND EXECUTION
// ============================================================================

void test_system_vulnerable_user_input(char *user_cmd) {
    // ruleid: Process-Control
    system(user_cmd);
}

void test_system_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Process-Control
    system(argv[1]);
}

void test_system_vulnerable_getenv() {
    // ruleid: Process-Control
    system(getenv("USER_COMMAND"));
}

void test_system_vulnerable_concat(char *user_arg) {
    char cmd[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(cmd, "ls -la %s", user_arg);
    // ruleid: Process-Control
    system(cmd);
}

void test_system_vulnerable_strcat(char *dir_name) {
    char cmd[MAX_CMD_LEN] = "cd ";
    // ruleid: Process-Control
    strcat(cmd, dir_name);
    // ruleid: Process-Control
    system(cmd);
}

void test_system_safe_literal() {
    // ok: Process-Control
    system("ls -la");
}

void test_system_safe_const() {
    // ok: Process-Control
    system(TRUSTED_CMD);
}

void test_system_safe_sanitized(char *user_input) {
    if (contains_shell_metachar(user_input)) {
        fprintf(stderr, "Invalid characters in command\n");
        return;
    }
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    // ok: Process-Control (sanitized)
    system(cmd);
}

void test_system_safe_allowlist(char *user_cmd) {
    if (!is_safe_command(user_cmd)) {
        fprintf(stderr, "Command not in allowlist\n");
        return;
    }
    // ok: Process-Control (allowlisted)
    system(user_cmd);
}

// ============================================================================
// SECTION 2: popen() - PIPE COMMAND EXECUTION
// ============================================================================

void test_popen_vulnerable(char *cmd) {
    // ruleid: Process-Control
    FILE *f = popen(cmd, "r");
    if (f) pclose(f);
}

void test_popen_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Process-Control
    FILE *f = popen(argv[1], "r");
    if (f) pclose(f);
}

void test_popen_vulnerable_concat(char *filename) {
    char cmd[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(cmd, "cat %s", filename);
    // ruleid: Process-Control
    FILE *f = popen(cmd, "r");
    if (f) pclose(f);
}

void test_popen_safe_literal() {
    // ok: Process-Control
    FILE *f = popen("ls -la", "r");
    if (f) pclose(f);
}

void test_popen_safe_const() {
    // ok: Process-Control
    FILE *f = popen(TRUSTED_COMMAND, "r");
    if (f) pclose(f);
}

// ============================================================================
// SECTION 3: exec* FAMILY - DIRECT PROCESS EXECUTION
// ============================================================================

void test_execl_vulnerable(char *path, char *arg) {
    // ruleid: Process-Control
    execl(path, arg, NULL);
}

void test_execvp_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Process-Control
    execvp(argv[1], &argv[1]);
}

void test_execle_vulnerable_getenv() {
    char *env[] = {getenv("USER_ENV"), NULL};
    // ruleid: Process-Control
    execle("/bin/sh", "sh", "-c", getenv("COMMAND"), NULL, env);
}

void test_execv_vulnerable(char *path, char *args[]) {
    // ruleid: Process-Control
    execv(path, args);
}

void test_execl_safe_literal() {
    // ok: Process-Control
    execl("/bin/ls", "ls", "-la", NULL);
}

void test_execvp_safe_const() {
    char *args[] = {TRUSTED_COMMAND, NULL};
    // ok: Process-Control
    execvp("/bin/echo", args);
}

// ============================================================================
// SECTION 4: LoadLibrary() - WINDOWS DYNAMIC LIBRARY LOADING
// ============================================================================

#ifdef _WIN32

void test_LoadLibraryA_vulnerable(char *lib_name) {
    // ruleid: Process-Control
    HMODULE h = LoadLibraryA(lib_name);
    if (h) FreeLibrary(h);
}

void test_LoadLibraryW_vulnerable(wchar_t *wlib_name) {
    // ruleid: Process-Control
    HMODULE h = LoadLibraryW(wlib_name);
    if (h) FreeLibrary(h);
}

void test_LoadLibraryExA_vulnerable(char *lib_path, char *user_dir) {
    char full_path[MAX_PATH];
    // ruleid: Process-Control
    sprintf(full_path, "%s\\%s", user_dir, lib_path);
    // ruleid: Process-Control
    HMODULE h = LoadLibraryExA(full_path, NULL, 0);
    if (h) FreeLibrary(h);
}

void test_LoadLibraryA_safe_literal() {
    // ok: Process-Control
    HMODULE h = LoadLibraryA("kernel32.dll");
    if (h) FreeLibrary(h);
}

void test_LoadLibraryW_safe_const() {
    // ok: Process-Control
    HMODULE h = LoadLibraryW(L"user32.dll");
    if (h) FreeLibrary(h);
}

#endif

// ============================================================================
// SECTION 5: dlopen() - POSIX DYNAMIC LIBRARY LOADING
// ============================================================================

void test_dlopen_vulnerable(char *lib_name) {
    // ruleid: Process-Control
    void *handle = dlopen(lib_name, RTLD_LAZY);
    if (handle) dlclose(handle);
}

void test_dlopen_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Process-Control
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (handle) dlclose(handle);
}

void test_dlopen_vulnerable_concat(char *plugin_name) {
    char path[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(path, "%s/%s.so", PLUGIN_DIR, plugin_name);
    // ruleid: Process-Control
    void *handle = dlopen(path, RTLD_LAZY);
    if (handle) dlclose(handle);
}

void test_dlsym_vulnerable(void *handle, char *symbol_name) {
    // ruleid: Process-Control
    void *func = dlsym(handle, symbol_name);
}

void test_dlopen_safe_literal() {
    // ok: Process-Control
    void *handle = dlopen("/usr/lib/libssl.so", RTLD_LAZY);
    if (handle) dlclose(handle);
}

void test_dlopen_safe_const() {
    // ok: Process-Control
    void *handle = dlopen(SAFE_LIB_PATH, RTLD_NOW);
    if (handle) dlclose(handle);
}

void test_dlsym_safe_literal() {
    void *handle = dlopen("/usr/lib/libtest.so", RTLD_LAZY);
    // ok: Process-Control
    void *func = dlsym(handle, "test_function");
    if (handle) dlclose(handle);
}

// ============================================================================
// SECTION 6: GetProcAddress() - WINDOWS FUNCTION ADDRESS
// ============================================================================

#ifdef _WIN32

void test_GetProcAddress_vulnerable(HMODULE hModule, char *proc_name) {
    // ruleid: Process-Control
    FARPROC proc = GetProcAddress(hModule, proc_name);
}

void test_GetProcAddress_vulnerable_argv(HMODULE hModule, int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Process-Control
    FARPROC proc = GetProcAddress(hModule, argv[1]);
}

void test_GetProcAddress_safe_literal() {
    HMODULE h = LoadLibraryA("kernel32.dll");
    // ok: Process-Control
    FARPROC proc = GetProcAddress(h, "GetProcAddress");
    if (h) FreeLibrary(h);
}

void test_GetModuleHandleA_vulnerable(char *module_name) {
    // ruleid: Process-Control
    HMODULE h = GetModuleHandleA(module_name);
}

void test_GetModuleHandleA_safe_literal() {
    // ok: Process-Control
    HMODULE h = GetModuleHandleA("kernel32.dll");
}

#endif

// ============================================================================
// SECTION 7: Environment Variable Manipulation
// ============================================================================

void test_setenv_vulnerable(char *var_name, char *var_value) {
    // ruleid: Process-Control
    setenv(var_name, var_value, 1);
}

void test_setenv_vulnerable_path(char *user_path) {
    // ruleid: Process-Control
    setenv("PATH", user_path, 1);
}

void test_setenv_vulnerable_ld_preload(char *lib_path) {
    // ruleid: Process-Control
    setenv("LD_PRELOAD", lib_path, 1);
}

void test_putenv_vulnerable(char *env_string) {
    // ruleid: Process-Control
    putenv(env_string);
}

void test_setenv_safe_literal() {
    // ok: Process-Control
    setenv("APP_MODE", "production", 1);
}

void test_setenv_safe_const() {
    // ok: Process-Control
    setenv("CONFIG_DIR", "/etc/myapp", 1);
}

void test_putenv_safe_literal() {
    // ok: Process-Control
    putenv("DEBUG=false");
}

// ============================================================================
// SECTION 8: CreateProcess() - WINDOWS PROCESS CREATION
// ============================================================================

#ifdef _WIN32

void test_CreateProcessA_vulnerable(char *app_name, char *cmd_line) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    // ruleid: Process-Control
    CreateProcessA(app_name, cmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void test_CreateProcessW_vulnerable(wchar_t *wcmd_line) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    // ruleid: Process-Control
    CreateProcessW(NULL, wcmd_line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void test_CreateProcessA_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    // ruleid: Process-Control
    CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void test_CreateProcessA_safe_literal() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    // ok: Process-Control
    CreateProcessA("notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

void test_ShellExecuteA_vulnerable(char *file, char *params) {
    // ruleid: Process-Control
    ShellExecuteA(NULL, "open", file, params, NULL, SW_SHOWNORMAL);
}

void test_ShellExecuteA_safe_literal() {
    // ok: Process-Control
    ShellExecuteA(NULL, "open", "notepad.exe", NULL, NULL, SW_SHOWNORMAL);
}

#endif

// ============================================================================
// SECTION 9: C++ SPECIFIC - std::system
// ============================================================================

#ifdef __cplusplus

void test_cpp_std_system_vulnerable(const std::string& cmd) {
    // ruleid: Process-Control
    std::system(cmd.c_str());
}

void test_cpp_std_system_vulnerable_char(char *cmd) {
    // ruleid: Process-Control
    std::system(cmd);
}

void test_cpp_std_system_safe_literal() {
    // ok: Process-Control
    std::system("ls -la");
}

#endif

// ============================================================================
// SECTION 10: C++ SPECIFIC - QProcess (Qt Framework)
// ============================================================================

#ifdef __cplusplus

void test_QProcess_start_vulnerable(const QString& program, const QStringList& args) {
    QProcess process;
    // ruleid: Process-Control
    process.start(program, args);
}

void test_QProcess_execute_vulnerable(const QString& command) {
    QProcess process;
    // ruleid: Process-Control
    process.execute(command);
}

void test_QProcess_startDetached_vulnerable(char *cmd) {
    // ruleid: Process-Control
    QProcess::startDetached(cmd);
}

void test_QProcess_start_safe_literal() {
    QProcess process;
    // ok: Process-Control
    process.start("ls", QStringList() << "-la");
}

void test_QProcess_execute_safe_const() {
    QProcess process;
    // ok: Process-Control
    process.execute(TRUSTED_CMD);
}

#endif

// ============================================================================
// SECTION 11: REAL-WORLD SCENARIO - PLUGIN LOADER
// ============================================================================

typedef struct {
    char *name;
    char *path;
    void *handle;
    int (*init)(void);
    int (*run)(void);
    void (*cleanup)(void);
} Plugin;

static Plugin *load_plugin_vulnerable(char *plugin_name, char *plugin_dir) {
    Plugin *plugin = malloc(sizeof(Plugin));
    char path[MAX_CMD_LEN];
    
    // ruleid: Process-Control
    sprintf(path, "%s/%s.so", plugin_dir, plugin_name);
    
#ifdef _WIN32
    // ruleid: Process-Control
    plugin->handle = LoadLibraryA(path);
#else
    // ruleid: Process-Control
    plugin->handle = dlopen(path, RTLD_LAZY);
#endif
    
    if (!plugin->handle) {
        free(plugin);
        return NULL;
    }
    
#ifdef _WIN32
    // ruleid: Process-Control
    plugin->init = (int (*)(void))GetProcAddress(plugin->handle, "plugin_init");
    // ruleid: Process-Control
    plugin->run = (int (*)(void))GetProcAddress(plugin->handle, "plugin_run");
#else
    // ruleid: Process-Control
    plugin->init = (int (*)(void))dlsym(plugin->handle, "plugin_init");
    // ruleid: Process-Control
    plugin->run = (int (*)(void))dlsym(plugin->handle, "plugin_run");
#endif
    
    return plugin;
}

static Plugin *load_plugin_safe(const char *plugin_name, const char *plugin_dir) {
    if (strstr(plugin_name, "..") != NULL) {
        fprintf(stderr, "Invalid plugin name\n");
        return NULL;
    }
    
    Plugin *plugin = malloc(sizeof(Plugin));
    char path[MAX_CMD_LEN];
    
    snprintf(path, sizeof(path), "%s/%s.so", plugin_dir, plugin_name);
    
#ifdef _WIN32
    // ok: Process-Control (sanitized)
    plugin->handle = LoadLibraryA(path);
#else
    // ok: Process-Control (sanitized)
    plugin->handle = dlopen(path, RTLD_LAZY);
#endif
    
    if (!plugin->handle) {
        free(plugin);
        return NULL;
    }
    
#ifdef _WIN32
    // ok: Process-Control (sanitized)
    plugin->init = (int (*)(void))GetProcAddress(plugin->handle, "plugin_init");
#else
    // ok: Process-Control (sanitized)
    plugin->init = (int (*)(void))dlsym(plugin->handle, "plugin_init");
#endif
    
    return plugin;
}

// ============================================================================
// SECTION 12: REAL-WORLD SCENARIO - COMMAND RUNNER
// ============================================================================

typedef struct {
    char *command;
    char *working_dir;
    char **env_vars;
    int timeout;
} CommandConfig;

static int run_command_vulnerable(CommandConfig *config) {
    char cmd[MAX_CMD_LEN];
    
    if (config->working_dir) {
        // ruleid: Process-Control
        sprintf(cmd, "cd %s && %s", config->working_dir, config->command);
    } else {
        // ruleid: Process-Control
        strcpy(cmd, config->command);
    }
    
    if (config->env_vars) {
        for (int i = 0; config->env_vars[i] != NULL; i++) {
            // ruleid: Process-Control
            putenv(config->env_vars[i]);
        }
    }
    
    // ruleid: Process-Control
    int ret = system(cmd);
    return ret;
}

static int run_command_safe(CommandConfig *config) {
    if (contains_shell_metachar(config->command)) {
        fprintf(stderr, "Invalid characters in command\n");
        return -1;
    }
    
    if (!is_safe_command(config->command)) {
        fprintf(stderr, "Command not in allowlist\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "%s", config->command);
    
    // ok: Process-Control (sanitized + allowlisted)
    int ret = system(cmd);
    return ret;
}

// ============================================================================
// SECTION 13: REAL-WORLD SCENARIO - CONFIGURATION LOADER
// ============================================================================

typedef struct {
    char config_path[MAX_CMD_LEN];
    char plugin_dir[MAX_CMD_LEN];
    char shell_cmd[MAX_CMD_LEN];
    int debug_mode;
} AppConfig;

static int load_config_vulnerable(AppConfig *config, char *config_file) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: Process-Control
    sprintf(cmd, "cat %s", config_file);
    // ruleid: Process-Control
    FILE *f = popen(cmd, "r");
    
    if (!f) return -1;
    
    // ruleid: Process-Control
    fgets(config->config_path, sizeof(config->config_path), f);
    // ruleid: Process-Control
    fgets(config->plugin_dir, sizeof(config->plugin_dir), f);
    // ruleid: Process-Control
    fgets(config->shell_cmd, sizeof(config->shell_cmd), f);
    
    pclose(f);
    
    // ruleid: Process-Control
    setenv("APP_CONFIG", config->config_path, 1);
    // ruleid: Process-Control
    setenv("PLUGIN_DIR", config->plugin_dir, 1);
    
    return 0;
}

static int load_config_safe(AppConfig *config, const char *config_file) {
    if (strstr(config_file, "..") != NULL) {
        fprintf(stderr, "Invalid config file path\n");
        return -1;
    }
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "cat %s", config_file);
    
    // ok: Process-Control (sanitized)
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    
    fgets(config->config_path, sizeof(config->config_path), f);
    fgets(config->plugin_dir, sizeof(config->plugin_dir), f);
    fgets(config->shell_cmd, sizeof(config->shell_cmd), f);
    
    pclose(f);
    
    // ok: Process-Control (sanitized)
    setenv("APP_CONFIG", config->config_path, 1);
    setenv("PLUGIN_DIR", config->plugin_dir, 1);
    
    return 0;
}

// ============================================================================
// SECTION 14: REAL-WORLD SCENARIO - BUILD SYSTEM
// ============================================================================

static int run_build_command_vulnerable(char *target, char *flags) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: Process-Control
    sprintf(cmd, "make %s %s", target, flags);
    // ruleid: Process-Control
    int ret = system(cmd);
    return ret;
}

static int run_build_command_safe(const char *target, const char *flags) {
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "make %s %s", target, flags);
    
    // ok: Process-Control (bounded, but still risky - depends on context)
    int ret = system(cmd);
    return ret;
}

// ============================================================================
// SECTION 15: EDGE CASES - MACROS AND CONSTANTS
// ============================================================================

void test_macro_command_vulnerable(char *extra_args) {
    char cmd[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(cmd, "%s %s", TRUSTED_CMD, extra_args);
    // ruleid: Process-Control
    system(cmd);
}

void test_const_library_vulnerable(char *lib_suffix) {
    char path[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(path, "%s%s", SAFE_LIB_PATH, lib_suffix);
    // ruleid: Process-Control
    dlopen(path, RTLD_LAZY);
}

void test_global_shell_vulnerable(char *script_name) {
    char cmd[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(cmd, "%s %s", g_default_shell, script_name);
    // ruleid: Process-Control
    system(cmd);
}

// ============================================================================
// SECTION 16: EDGE CASES - MULTIPLE INPUT SOURCES
// ============================================================================

void test_multiple_sources_vulnerable(int argc, char *argv[], char *user_input) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: Process-Control
    sprintf(cmd, "%s %s %s", argv[1], getenv("EXTRA_ARGS"), user_input);
    // ruleid: Process-Control
    system(cmd);
}

void test_nested_function_vulnerable(char *input) {
    char cmd[MAX_CMD_LEN];
    // ruleid: Process-Control
    sprintf(cmd, "echo %s", input);
    // ruleid: Process-Control
    system(strcpy(cmd, cmd));
}

// ============================================================================
// SECTION 17: EDGE CASES - WIDE CHARACTER FUNCTIONS
// ============================================================================

void test_wsystem_vulnerable(wchar_t *wcmd) {
    // ruleid: Process-Control
    _wsystem(wcmd);
}

void test_wpopen_vulnerable(wchar_t *wcmd) {
    // ruleid: Process-Control
    FILE *f = _wpopen(wcmd, L"r");
    if (f) pclose(f);
}

void test_wsystem_safe_literal() {
    // ok: Process-Control
    _wsystem(L"dir");
}

// ============================================================================
// SECTION 18: EDGE CASES - FUNCTION POINTERS AND CALLBACKS
// ============================================================================

typedef int (*CommandExecutor)(const char *cmd);

static int execute_with_callback_vulnerable(CommandExecutor exec, char *user_cmd) {
    // ruleid: Process-Control
    return exec(user_cmd);
}

static int execute_with_callback_safe(CommandExecutor exec, const char *cmd) {
    if (!is_safe_command(cmd)) {
        return -1;
    }
    // ok: Process-Control (validated)
    return exec(cmd);
}

// ============================================================================
// SECTION 19: EDGE CASES - ENVIRONMENT INHERITANCE
// ============================================================================

void test_inherit_environment_vulnerable(char *new_path) {
    // ruleid: Process-Control
    setenv("PATH", new_path, 1);
    // ruleid: Process-Control
    setenv("LD_LIBRARY_PATH", new_path, 1);
    // ruleid: Process-Control
    system("some_command");
}

void test_clean_environment_safe() {
    // ok: Process-Control
    setenv("PATH", "/usr/bin:/bin", 1);
    // ok: Process-Control
    setenv("LD_LIBRARY_PATH", "/usr/lib", 1);
    // ok: Process-Control
    system("ls -la");
}

// ============================================================================
// SECTION 20: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Process Control Test Suite\n");
    
    // Safe operations
    test_system_safe_literal();
    test_popen_safe_literal();
    test_execl_safe_literal();
    test_dlopen_safe_literal();
    test_setenv_safe_literal();
    
#ifdef _WIN32
    test_LoadLibraryA_safe_literal();
    test_CreateProcessA_safe_literal();
#endif

#ifdef __cplusplus
    test_cpp_std_system_safe_literal();
    test_QProcess_start_safe_literal();
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