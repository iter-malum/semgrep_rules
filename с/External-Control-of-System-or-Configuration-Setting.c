// test_external_control.c
// Comprehensive test suite for CWE-15: External Control of System or Configuration Setting
// Compile with: gcc -Wall -Wextra -std=c11 test_external_control.c -o test_external_control
// C++ Compile: g++ -Wall -Wextra -std=c++17 test_external_control.c -o test_external_control

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#ifdef __cplusplus
#include <cstdlib>
#include <cstring>
#include <iostream>
#endif

// ============================================================================
// GLOBAL CONSTANTS AND TYPE DEFINITIONS
// ============================================================================

#define MAX_PATH_LEN 1024
#define MAX_ENV_VAR_LEN 512
#define MAX_CMD_LEN 2048
#define CONFIG_PATH "/etc/app/config.ini"
#define SAFE_PATH "/usr/bin/safe_tool"

typedef struct {
    char *env_name;
    char *env_value;
    char *config_path;
    int permissions;
} SystemConfig;

typedef struct {
    char *username;
    char *home_dir;
    int user_id;
    int group_id;
} UserContext;

// ============================================================================
// HELPER FUNCTIONS FOR VALIDATION
// ============================================================================

static int is_safe_env_name(const char *name) {
    const char *safe_names[] = {"APP_MODE", "LOG_LEVEL", "CONFIG_DIR", NULL};
    for (int i = 0; safe_names[i] != NULL; i++) {
        if (strcmp(name, safe_names[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int is_safe_path(const char *path) {
    if (strstr(path, "..") != NULL) {
        return 0;
    }
    if (path[0] != '/') {
        return 0;
    }
    const char *safe_prefixes[] = {"/usr/", "/var/", "/tmp/", "/home/", NULL};
    for (int i = 0; safe_prefixes[i] != NULL; i++) {
        if (strncmp(path, safe_prefixes[i], strlen(safe_prefixes[i])) == 0) {
            return 1;
        }
    }
    return 0;
}

static int validate_env_value(const char *value) {
    const char *dangerous_chars = ";|&$`\\\"'<>(){}[]!#*?";
    for (int i = 0; dangerous_chars[i] != '\0'; i++) {
        if (strchr(value, dangerous_chars[i]) != NULL) {
            return 0;
        }
    }
    return 1;
}

// ============================================================================
// SECTION 1: ENVIRONMENT VARIABLE MANIPULATION
// ============================================================================

void test_setenv_vulnerable(const char *env_name, const char *env_value) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(env_name, env_value, 1);
}

void test_setenv_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 3) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(argv[1], argv[2], 1);
}

void test_setenv_vulnerable_getenv() {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("PATH", getenv("USER_PATH"), 1);
}

void test_setenv_vulnerable_concat(const char *user_value) {
    char env_string[MAX_ENV_VAR_LEN];
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(env_string, sizeof(env_string), "CUSTOM_VAR=%s", user_value);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    putenv(env_string);
}

void test_setenv_safe_validated(const char *env_name, const char *env_value) {
    if (!is_safe_env_name(env_name)) {
        fprintf(stderr, "Unsafe environment variable name\n");
        return;
    }
    if (!validate_env_value(env_value)) {
        fprintf(stderr, "Unsafe environment variable value\n");
        return;
    }
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv(env_name, env_value, 1);
}

void test_setenv_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("APP_MODE", "production", 1);
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("LOG_LEVEL", "INFO", 1);
}

void test_putenv_vulnerable(const char *env_string) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    putenv(env_string);
}

void test_putenv_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    putenv(argv[1]);
}

void test_putenv_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    putenv("DEBUG=false");
    // ok: External-Control-of-System-or-Configuration-Setting
    putenv("TZ=UTC");
}

// ============================================================================
// SECTION 2: COMMAND EXECUTION WITH EXTERNAL INPUT
// ============================================================================

void test_system_vulnerable(const char *command) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(command);
}

void test_system_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(argv[1]);
}

void test_system_vulnerable_concat(const char *user_input) {
    char cmd[MAX_CMD_LEN];
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
}

void test_system_vulnerable_getenv() {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(getenv("USER_COMMAND"));
}

void test_system_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    system("ls -la");
    // ok: External-Control-of-System-or-Configuration-Setting
    system("/usr/bin/safe_tool --version");
}

void test_system_safe_validated(const char *user_input) {
    if (!validate_env_value(user_input)) {
        fprintf(stderr, "Invalid input\n");
        return;
    }
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "echo %s", user_input);
    // ok: External-Control-of-System-or-Configuration-Setting
    system(cmd);
}

void test_popen_vulnerable(const char *command) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    FILE *f = popen(command, "r");
    if (f) pclose(f);
}

void test_popen_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    FILE *f = popen(argv[1], "r");
    if (f) pclose(f);
}

void test_popen_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    FILE *f = popen("ls -la", "r");
    if (f) pclose(f);
}

// ============================================================================
// SECTION 3: EXEC FAMILY FUNCTIONS
// ============================================================================

void test_execl_vulnerable(const char *path, const char *arg) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    execl(path, arg, NULL);
}

void test_execl_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    execl(argv[1], argv[1], NULL);
}

void test_execv_vulnerable(const char *path, char *const args[]) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    execv(path, args);
}

void test_execvp_vulnerable(const char *file, char *const args[]) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    execvp(file, args);
}

void test_execl_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    execl("/usr/bin/ls", "ls", "-la", NULL);
}

void test_execv_safe_constant() {
    char *args[] = {"/usr/bin/ls", "-la", NULL};
    // ok: External-Control-of-System-or-Configuration-Setting
    execv("/usr/bin/ls", args);
}

// ============================================================================
// SECTION 4: FILE PERMISSION MODIFICATION
// ============================================================================

void test_chmod_vulnerable(const char *path, const char *mode_str) {
    mode_t mode = strtol(mode_str, NULL, 8);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(path, mode);
}

void test_chmod_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 3) return;
    mode_t mode = strtol(argv[2], NULL, 8);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(argv[1], mode);
}

void test_chmod_vulnerable_user_input(const char *path, mode_t mode) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(path, mode);
}

void test_chmod_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod("/var/log/app.log", 0644);
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod("/tmp/data", 0755);
}

void test_chmod_safe_validated(const char *path, mode_t mode) {
    if (!is_safe_path(path)) {
        fprintf(stderr, "Unsafe path\n");
        return;
    }
    if (mode > 0777) {
        fprintf(stderr, "Invalid mode\n");
        return;
    }
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(path, mode);
}

void test_chown_vulnerable(const char *path, const char *owner_str, const char *group_str) {
    uid_t uid = strtol(owner_str, NULL, 10);
    gid_t gid = strtol(group_str, NULL, 10);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(path, uid, gid);
}

void test_chown_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 4) return;
    uid_t uid = strtol(argv[2], NULL, 10);
    gid_t gid = strtol(argv[3], NULL, 10);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(argv[1], uid, gid);
}

void test_chown_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    chown("/var/log/app.log", 1000, 1000);
}

// ============================================================================
// SECTION 5: MOUNT/UMOUNT OPERATIONS
// ============================================================================

void test_mount_vulnerable(const char *source, const char *target, const char *filesystemtype) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount(source, target, filesystemtype, 0, NULL);
}

void test_mount_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 4) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount(argv[1], argv[2], argv[3], 0, NULL);
}

void test_mount_vulnerable_user_input(const char *target) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount("/dev/sdb1", target, "ext4", 0, NULL);
}

void test_mount_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    mount("/dev/sdb1", "/mnt/data", "ext4", 0, NULL);
}

void test_mount_safe_validated(const char *target) {
    if (!is_safe_path(target)) {
        fprintf(stderr, "Unsafe mount target\n");
        return;
    }
    // ok: External-Control-of-System-or-Configuration-Setting
    mount("/dev/sdb1", target, "ext4", 0, NULL);
}

void test_umount_vulnerable(const char *target) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    umount(target);
}

void test_umount_vulnerable_argv(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    umount(argv[1]);
}

void test_umount_safe_constant() {
    // ok: External-Control-of-System-or-Configuration-Setting
    umount("/mnt/data");
}

// ============================================================================
// SECTION 6: REAL-WORLD SCENARIO - CONFIGURATION LOADER
// ============================================================================

SystemConfig *load_system_config_vulnerable(int argc, char *argv[]) {
    SystemConfig *config = malloc(sizeof(SystemConfig));
    if (!config) return NULL;
    
    if (argc >= 2) {
        // ruleid: External-Control-of-System-or-Configuration-Setting
        config->env_name = argv[1];
    }
    if (argc >= 3) {
        // ruleid: External-Control-of-System-or-Configuration-Setting
        config->env_value = argv[2];
    }
    if (argc >= 4) {
        // ruleid: External-Control-of-System-or-Configuration-Setting
        config->config_path = argv[3];
    }
    if (argc >= 5) {
        // ruleid: External-Control-of-System-or-Configuration-Setting
        config->permissions = strtol(argv[4], NULL, 8);
    }
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(config->env_name, config->env_value, 1);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(config->config_path, config->permissions);
    
    return config;
}

SystemConfig *load_system_config_safe(int argc, char *argv[]) {
    SystemConfig *config = malloc(sizeof(SystemConfig));
    if (!config) return NULL;
    
    if (argc >= 2) {
        if (!is_safe_env_name(argv[1])) {
            fprintf(stderr, "Invalid env name\n");
            free(config);
            return NULL;
        }
        config->env_name = argv[1];
    }
    if (argc >= 3) {
        if (!validate_env_value(argv[2])) {
            fprintf(stderr, "Invalid env value\n");
            free(config);
            return NULL;
        }
        config->env_value = argv[2];
    }
    if (argc >= 4) {
        if (!is_safe_path(argv[3])) {
            fprintf(stderr, "Invalid path\n");
            free(config);
            return NULL;
        }
        config->config_path = argv[3];
    }
    if (argc >= 5) {
        config->permissions = strtol(argv[4], NULL, 8);
        if (config->permissions > 0777) {
            fprintf(stderr, "Invalid permissions\n");
            free(config);
            return NULL;
        }
    }
    
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv(config->env_name, config->env_value, 1);
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(config->config_path, config->permissions);
    
    return config;
}

// ============================================================================
// SECTION 7: REAL-WORLD SCENARIO - USER MANAGEMENT
// ============================================================================

UserContext *create_user_context_vulnerable(const char *username, const char *home_dir) {
    UserContext *ctx = malloc(sizeof(UserContext));
    if (!ctx) return NULL;
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    ctx->username = username;
    // ruleid: External-Control-of-System-or-Configuration-Setting
    ctx->home_dir = home_dir;
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("USER", username);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("HOME", home_dir);
    
    char cmd[MAX_CMD_LEN];
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", home_dir);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(home_dir, ctx->user_id, ctx->group_id);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(home_dir, 0700);
    
    return ctx;
}

UserContext *create_user_context_safe(const char *username, const char *home_dir) {
    UserContext *ctx = malloc(sizeof(UserContext));
    if (!ctx) return NULL;
    
    if (!validate_env_value(username)) {
        fprintf(stderr, "Invalid username\n");
        free(ctx);
        return NULL;
    }
    if (!is_safe_path(home_dir)) {
        fprintf(stderr, "Invalid home directory\n");
        free(ctx);
        return NULL;
    }
    
    ctx->username = username;
    ctx->home_dir = home_dir;
    
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("USER", username);
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("HOME", home_dir);
    
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", home_dir);
    // ok: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ok: External-Control-of-System-or-Configuration-Setting
    chown(home_dir, ctx->user_id, ctx->group_id);
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(home_dir, 0700);
    
    return ctx;
}

// ============================================================================
// SECTION 8: REAL-WORLD SCENARIO - SYSTEM ADMINISTRATOR
// ============================================================================

void admin_set_environment_vulnerable(const char *var_name, const char *var_value) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(var_name, var_value, 1);
}

void admin_execute_command_vulnerable(const char *command) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(command);
}

void admin_modify_permissions_vulnerable(const char *path, mode_t mode) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(path, mode);
}

void admin_change_ownership_vulnerable(const char *path, uid_t uid, gid_t gid) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(path, uid, gid);
}

void admin_mount_filesystem_vulnerable(const char *source, const char *target) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount(source, target, "ext4", 0, NULL);
}

void admin_unmount_filesystem_vulnerable(const char *target) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    umount(target);
}

void admin_operations_safe(const char *var_name, const char *var_value, const char *path) {
    if (!is_safe_env_name(var_name)) {
        fprintf(stderr, "Invalid environment variable name\n");
        return;
    }
    if (!validate_env_value(var_value)) {
        fprintf(stderr, "Invalid environment variable value\n");
        return;
    }
    if (!is_safe_path(path)) {
        fprintf(stderr, "Invalid path\n");
        return;
    }
    
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv(var_name, var_value, 1);
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(path, 0644);
}

// ============================================================================
// SECTION 9: REAL-WORLD SCENARIO - DEPLOYMENT SCRIPT
// ============================================================================

void deploy_application_vulnerable(const char *app_path, const char *config_path, const char *env_vars) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("APP_PATH", app_path);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("CONFIG_PATH", config_path);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    putenv(env_vars);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "chmod +x %s", app_path);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(config_path, 0644);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "%s --deploy", app_path);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
}

void deploy_application_safe(const char *app_path, const char *config_path, const char *env_vars) {
    char cmd[MAX_CMD_LEN];
    
    if (!is_safe_path(app_path) || !is_safe_path(config_path)) {
        fprintf(stderr, "Invalid paths\n");
        return;
    }
    if (!validate_env_value(env_vars)) {
        fprintf(stderr, "Invalid environment variables\n");
        return;
    }
    
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("APP_PATH", app_path);
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("CONFIG_PATH", config_path);
    
    // ok: External-Control-of-System-or-Configuration-Setting
    putenv(env_vars);
    
    snprintf(cmd, sizeof(cmd), "chmod +x %s", app_path);
    // ok: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(config_path, 0644);
    
    snprintf(cmd, sizeof(cmd), "%s --deploy", app_path);
    // ok: External-Control-of-System-or-Configuration-Setting
    system(cmd);
}

// ============================================================================
// SECTION 10: REAL-WORLD SCENARIO - CONTAINER MANAGER
// ============================================================================

void setup_container_vulnerable(const char *mount_point, const char *container_root) {
    char cmd[MAX_CMD_LEN];
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount("/dev/loop0", mount_point, "ext4", 0, NULL);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", container_root);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(container_root, 0755);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(container_root, 1000, 1000);
    
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("CONTAINER_ROOT", container_root);
}

void setup_container_safe(const char *mount_point, const char *container_root) {
    char cmd[MAX_CMD_LEN];
    
    if (!is_safe_path(mount_point) || !is_safe_path(container_root)) {
        fprintf(stderr, "Invalid paths\n");
        return;
    }
    
    // ok: External-Control-of-System-or-Configuration-Setting
    mount("/dev/loop0", mount_point, "ext4", 0, NULL);
    
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", container_root);
    // ok: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(container_root, 0755);
    // ok: External-Control-of-System-or-Configuration-Setting
    chown(container_root, 1000, 1000);
    
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("CONTAINER_ROOT", container_root);
}

// ============================================================================
// SECTION 11: EDGE CASES - MULTIPLE INPUT SOURCES
// ============================================================================

void test_multiple_sources_vulnerable(int argc, char *argv[], const char *env_input) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(argv[1], argv[2], 1);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    putenv(env_input);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(argv[3]);
}

void test_nested_calls_vulnerable(const char *path) {
    char cmd[MAX_CMD_LEN];
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "chmod 755 %s", path);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(path, 0755);
}

// ============================================================================
// SECTION 12: EDGE CASES - C++ SPECIFIC
// ============================================================================

#ifdef __cplusplus

void test_cpp_setenv_vulnerable(const std::string& name, const std::string& value) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv(name.c_str(), value.c_str(), 1);
}

void test_cpp_system_vulnerable(const std::string& cmd) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    std::system(cmd.c_str());
}

void test_cpp_safe() {
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("CPP_VAR", "value", 1);
    // ok: External-Control-of-System-or-Configuration-Setting
    std::system("ls -la");
}

#endif

// ============================================================================
// SECTION 13: EDGE CASES - SPECIAL CHARACTERS IN INPUT
// ============================================================================

void test_special_chars_vulnerable(const char *input_with_semicolon) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    setenv("TEST_VAR", input_with_semicolon, 1);
}

void test_special_chars_vulnerable_pipe(const char *input_with_pipe) {
    char cmd[MAX_CMD_LEN];
    // ruleid: External-Control-of-System-or-Configuration-Setting
    snprintf(cmd, sizeof(cmd), "echo %s", input_with_pipe);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    system(cmd);
}

void test_special_chars_safe(const char *input) {
    if (!validate_env_value(input)) {
        fprintf(stderr, "Invalid characters in input\n");
        return;
    }
    // ok: External-Control-of-System-or-Configuration-Setting
    setenv("TEST_VAR", input, 1);
}

// ============================================================================
// SECTION 14: EDGE CASES - PATH TRAVERSAL
// ============================================================================

void test_path_traversal_vulnerable(const char *user_path) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chmod(user_path, 0755);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    chown(user_path, 0, 0);
}

void test_path_traversal_vulnerable_mount(const char *user_mount_point) {
    // ruleid: External-Control-of-System-or-Configuration-Setting
    mount("/dev/sda1", user_mount_point, "ext4", 0, NULL);
    // ruleid: External-Control-of-System-or-Configuration-Setting
    umount(user_mount_point);
}

void test_path_traversal_safe(const char *user_path) {
    if (!is_safe_path(user_path)) {
        fprintf(stderr, "Path traversal detected\n");
        return;
    }
    // ok: External-Control-of-System-or-Configuration-Setting
    chmod(user_path, 0755);
    // ok: External-Control-of-System-or-Configuration-Setting
    chown(user_path, 0, 0);
}

// ============================================================================
// SECTION 15: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("External Control of System or Configuration Setting Test Suite\n");
    
    // Safe operations
    test_setenv_safe_constant();
    test_putenv_safe_constant();
    test_system_safe_constant();
    test_popen_safe_constant();
    test_execl_safe_constant();
    test_execv_safe_constant();
    test_chmod_safe_constant();
    test_chown_safe_constant();
    test_mount_safe_constant();
    test_umount_safe_constant();
    
#ifdef __cplusplus
    test_cpp_safe();
#endif
    
    // Vulnerable operations (only run with specific test flags)
    if (argc > 1 && strcmp(argv[1], "--test-vuln") == 0) {
        printf("Running vulnerable test cases...\n");
        
        test_setenv_vulnerable("TEST", "VALUE");
        test_system_vulnerable("ls -la");
        test_chmod_vulnerable("/tmp/test", "0755");
        
        deploy_application_vulnerable("/app/myapp", "/etc/myapp.conf", "DEBUG=1");
    }
    
    printf("Test compilation successful\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

static int mount(const char *source, const char *target, const char *filesystemtype, 
                 unsigned long mountflags, const void *data) {
    return 0;
}

static int umount(const char *target) {
    return 0;
}

static int chown(const char *path, uid_t owner, gid_t group) {
    return 0;
}

static int chmod(const char *path, mode_t mode) {
    return 0;
}