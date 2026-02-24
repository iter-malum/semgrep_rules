// test_excessive_malloc.c
// Comprehensive test suite for CWE-789: Memory Allocation with Excessive Size Value
// Compile with: gcc -Wall -Wextra -std=c11 test_excessive_malloc.c -o test_excessive_malloc
// C++ Compile: g++ -Wall -Wextra -std=c++17 test_excessive_malloc.c -o test_excessive_malloc

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#ifdef __cplusplus
#include <new>
#include <vector>
#include <iostream>
#endif

// ============================================================================
// GLOBAL CONSTANTS AND TYPE DEFINITIONS
// ============================================================================

#define MAX_BUFFER_SIZE 65536
#define MAX_ALLOC_SIZE 1048576
#define MAX_WIDTH 4096
#define MAX_HEIGHT 4096
#define MAX_COUNT 10000
#define MAX_USERS 1000

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t depth;
    uint32_t data_size;
    char *data;
} ImageHeader;

typedef struct {
    uint32_t count;
    uint32_t item_size;
    void **items;
} Collection;

typedef struct {
    uint32_t user_count;
    uint32_t session_size;
    char **sessions;
} SessionManager;

typedef struct {
    uint32_t packet_size;
    uint32_t chunk_count;
    uint8_t *buffer;
} NetworkPacket;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static uint32_t read_uint32_from_network(int sockfd) {
    uint32_t value;
    recv(sockfd, &value, sizeof(value), 0);
    return value;
}

static uint32_t parse_header_field(const char *header, const char *field) {
    // Simulated header parsing
    return atoi(field);
}

static int validate_size(uint32_t size, uint32_t max) {
    return size <= max;
}

// ============================================================================
// SECTION 1: UNTRUSTED SIZE FROM COMMAND LINE ARGUMENTS
// ============================================================================

void test_argv_malloc_vulnerable(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t size = atoi(argv[1]);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
        free(buffer);
    }
}

void test_argv_calloc_vulnerable(int argc, char *argv[]) {
    if (argc < 3) return;
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t count = atoi(argv[1]);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t item_size = atoi(argv[2]);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void **array = calloc(count, item_size);
    if (array) free(array);
}

void test_argv_realloc_vulnerable(int argc, char *argv[]) {
    if (argc < 2) return;
    char *buffer = malloc(1024);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t new_size = atoi(argv[1]);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    buffer = realloc(buffer, new_size);
    if (buffer) free(buffer);
}

void test_argv_malloc_safe(int argc, char *argv[]) {
    if (argc < 2) return;
    size_t size = atoi(argv[1]);
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Size too large\n");
        return;
    }
    char *buffer = malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
        free(buffer);
    }
}

void test_argv_calloc_safe(int argc, char *argv[]) {
    if (argc < 3) return;
    size_t count = atoi(argv[1]);
    size_t item_size = atoi(argv[2]);
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (count > MAX_COUNT || item_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Invalid parameters\n");
        return;
    }
    void **array = calloc(count, item_size);
    if (array) free(array);
}

// ============================================================================
// SECTION 2: INTEGER OVERFLOW IN SIZE CALCULATIONS
// ============================================================================

void test_integer_overflow_multiply_vulnerable(uint32_t width, uint32_t height) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(width * height);
    if (buffer) free(buffer);
}

void test_integer_overflow_3d_vulnerable(uint32_t width, uint32_t height, uint32_t depth) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(width * height * depth);
    if (buffer) free(buffer);
}

void test_integer_overflow_calloc_vulnerable(uint32_t count, uint32_t item_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void *array = calloc(count, item_size);
    if (array) free(array);
}

void test_integer_overflow_safe(uint32_t width, uint32_t height) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (width > MAX_WIDTH || height > MAX_HEIGHT) {
        fprintf(stderr, "Dimensions too large\n");
        return;
    }
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (width > 0 && height > SIZE_MAX / width) {
        fprintf(stderr, "Overflow detected\n");
        return;
    }
    char *buffer = malloc(width * height);
    if (buffer) free(buffer);
}

void test_integer_overflow_with_sizeof_safe(uint32_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    int *array = malloc(count * sizeof(int));
    if (array) free(array);
}

void test_calloc_with_sizeof_safe(uint32_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    int *array = calloc(count, sizeof(int));
    if (array) free(array);
}

// ============================================================================
// SECTION 3: STACK VARIABLE LENGTH ARRAYS (VLA)
// ============================================================================

void test_vla_stack_vulnerable(size_t user_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char stack_buffer[user_size];
    memset(stack_buffer, 0, user_size);
}

void test_vla_stack_mult_vulnerable(size_t count, size_t item_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char stack_buffer[count * item_size];
    memset(stack_buffer, 0, count * item_size);
}

void test_vla_stack_uint8_vulnerable(size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint8_t buffer[size];
    memset(buffer, 0, size);
}

void test_vla_stack_int_vulnerable(size_t count) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    int array[count];
    memset(array, 0, count * sizeof(int));
}

void test_vla_stack_safe(size_t user_size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (user_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Size too large for stack\n");
        return;
    }
    char stack_buffer[user_size];
    memset(stack_buffer, 0, user_size);
}

void test_vla_stack_const_safe() {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    char stack_buffer[1024];
    memset(stack_buffer, 0, sizeof(stack_buffer));
}

// ============================================================================
// SECTION 4: C++ NEW[] WITH UNTRUSTED SIZE
// ============================================================================

#ifdef __cplusplus

void test_cpp_new_array_vulnerable(size_t count) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *array = new char[count];
    delete[] array;
}

void test_cpp_new_array_mult_vulnerable(size_t count, size_t item_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *array = new char[count * item_size];
    delete[] array;
}

void test_cpp_new_array_argv_vulnerable(int argc, char *argv[]) {
    if (argc < 2) return;
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t count = atoi(argv[1]);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *array = new char[count];
    delete[] array;
}

void test_cpp_new_array_safe(size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (count > MAX_ALLOC_SIZE) {
        std::cerr << "Count too large" << std::endl;
        return;
    }
    char *array = new char[count];
    delete[] array;
}

void test_cpp_new_array_sizeof_safe(size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    int *array = new int[count];
    delete[] array;
}

void test_cpp_vector_safe(size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    std::vector<char> vec(count);
}

#endif

// ============================================================================
// SECTION 5: NETWORK DATA AS SIZE
// ============================================================================

void test_network_recv_size_vulnerable(int sockfd) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint32_t packet_size = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint8_t *buffer = malloc(packet_size);
    if (buffer) {
        recv(sockfd, buffer, packet_size, 0);
        free(buffer);
    }
}

void test_network_chunk_count_vulnerable(int sockfd) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint32_t chunk_count = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint32_t chunk_size = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    uint8_t *buffer = malloc(chunk_count * chunk_size);
    if (buffer) free(buffer);
}

void test_network_recv_size_safe(int sockfd) {
    uint32_t packet_size = read_uint32_from_network(sockfd);
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (packet_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Packet too large\n");
        return;
    }
    uint8_t *buffer = malloc(packet_size);
    if (buffer) {
        recv(sockfd, buffer, packet_size, 0);
        free(buffer);
    }
}

// ============================================================================
// SECTION 6: STRUCT FIELD AS SIZE
// ============================================================================

void test_struct_field_size_vulnerable(ImageHeader *header) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->data = malloc(header->data_size);
}

void test_struct_field_mult_vulnerable(ImageHeader *header) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->data = malloc(header->width * header->height);
}

void test_collection_count_vulnerable(Collection *col) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    col->items = malloc(col->count * col->item_size);
}

void test_session_manager_vulnerable(SessionManager *mgr) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    mgr->sessions = malloc(mgr->user_count * mgr->session_size);
}

void test_struct_field_size_safe(ImageHeader *header) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (header->data_size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Data size too large\n");
        return;
    }
    header->data = malloc(header->data_size);
}

void test_struct_field_mult_safe(ImageHeader *header) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (header->width > MAX_WIDTH || header->height > MAX_HEIGHT) {
        fprintf(stderr, "Dimensions too large\n");
        return;
    }
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (header->width > 0 && header->height > SIZE_MAX / header->width) {
        fprintf(stderr, "Overflow detected\n");
        return;
    }
    header->data = malloc(header->width * header->height);
}

// ============================================================================
// SECTION 7: MISSING NULL CHECK AFTER ALLOCATION
// ============================================================================

void test_missing_null_check_malloc_vulnerable(size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    memset(buffer, 0, size);
    free(buffer);
}

void test_missing_null_check_calloc_vulnerable(size_t count, size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void *array = calloc(count, size);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    memset(array, 0, count * size);
    free(array);
}

void test_missing_null_check_realloc_vulnerable(char *old_buffer, size_t new_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *new_buffer = realloc(old_buffer, new_size);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    memset(new_buffer, 0, new_size);
}

void test_null_check_safe(size_t size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Allocation failed\n");
        return;
    }
    memset(buffer, 0, size);
    free(buffer);
}

void test_null_check_safe_not_operator(size_t size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (!buffer) {
        fprintf(stderr, "Allocation failed\n");
        return;
    }
    memset(buffer, 0, size);
    free(buffer);
}

// ============================================================================
// SECTION 8: MISSING BOUNDS CHECK BEFORE ALLOCATION
// ============================================================================

void test_missing_bounds_check_vulnerable(size_t user_size) {
    // No validation of user_size
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(user_size);
    if (buffer) {
        memset(buffer, 0, user_size);
        free(buffer);
    }
}

void test_missing_bounds_check_params_vulnerable(size_t count, size_t item_size) {
    // No validation of parameters
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void *array = calloc(count, item_size);
    if (array) free(array);
}

void test_bounds_check_safe(size_t user_size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (user_size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Size exceeds maximum\n");
        return;
    }
    char *buffer = malloc(user_size);
    if (buffer) {
        memset(buffer, 0, user_size);
        free(buffer);
    }
}

void test_bounds_check_safe_less_equal(size_t user_size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (user_size <= MAX_ALLOC_SIZE) {
        char *buffer = malloc(user_size);
        if (buffer) {
            memset(buffer, 0, user_size);
            free(buffer);
        }
    }
}

void test_bounds_check_assert_safe(size_t user_size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    assert(user_size < MAX_ALLOC_SIZE);
    char *buffer = malloc(user_size);
    if (buffer) {
        memset(buffer, 0, user_size);
        free(buffer);
    }
}

// ============================================================================
// SECTION 9: FUNCTION PARAMETER AS SIZE
// ============================================================================

void test_function_param_size_vulnerable(size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
        free(buffer);
    }
}

void test_function_param_calloc_vulnerable(size_t count, size_t item_size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void *array = calloc(count, item_size);
    if (array) free(array);
}

void test_function_param_new_vulnerable(size_t count) {
#ifdef __cplusplus
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *array = new char[count];
    delete[] array;
#endif
}

void test_function_param_safe(size_t size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Size parameter too large\n");
        return;
    }
    char *buffer = malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
        free(buffer);
    }
}

// ============================================================================
// SECTION 10: PARSED INPUT AS SIZE
// ============================================================================

void test_parsed_input_vulnerable(const char *input) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t size = atoi(input);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer) free(buffer);
}

void test_strtol_vulnerable(const char *input) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    size_t size = strtol(input, NULL, 10);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer) free(buffer);
}

void test_sscanf_vulnerable(const char *input) {
    size_t size;
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    sscanf(input, "%zu", &size);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(size);
    if (buffer) free(buffer);
}

void test_parsed_input_safe(const char *input) {
    size_t size = atoi(input);
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Parsed size too large\n");
        return;
    }
    char *buffer = malloc(size);
    if (buffer) free(buffer);
}

// ============================================================================
// SECTION 11: ARRAY INDEX AS SIZE
// ============================================================================

void test_array_index_size_vulnerable(uint32_t *sizes, uint32_t index) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(sizes[index]);
    if (buffer) free(buffer);
}

void test_array_index_calloc_vulnerable(uint32_t *counts, uint32_t *item_sizes, uint32_t index) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    void *array = calloc(counts[index], item_sizes[index]);
    if (array) free(array);
}

void test_array_index_safe(uint32_t *sizes, uint32_t index) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (sizes[index] > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Array size too large\n");
        return;
    }
    char *buffer = malloc(sizes[index]);
    if (buffer) free(buffer);
}

// ============================================================================
// SECTION 12: REAL-WORLD SCENARIO - IMAGE PROCESSOR
// ============================================================================

ImageHeader *load_image_header_vulnerable(int sockfd) {
    ImageHeader *header = malloc(sizeof(ImageHeader));
    if (!header) return NULL;
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->width = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->height = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->depth = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->data_size = read_uint32_from_network(sockfd);
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    header->data = malloc(header->data_size);
    if (!header->data) {
        free(header);
        return NULL;
    }
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    recv(sockfd, header->data, header->data_size, 0);
    return header;
}

ImageHeader *load_image_header_safe(int sockfd) {
    ImageHeader *header = malloc(sizeof(ImageHeader));
    if (!header) return NULL;
    
    header->width = read_uint32_from_network(sockfd);
    header->height = read_uint32_from_network(sockfd);
    header->depth = read_uint32_from_network(sockfd);
    header->data_size = read_uint32_from_network(sockfd);
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (header->width > MAX_WIDTH || header->height > MAX_HEIGHT) {
        fprintf(stderr, "Invalid dimensions\n");
        free(header);
        return NULL;
    }
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (header->data_size > MAX_ALLOC_SIZE) {
        fprintf(stderr, "Data size too large\n");
        free(header);
        return NULL;
    }
    
    header->data = malloc(header->data_size);
    if (!header->data) {
        free(header);
        return NULL;
    }
    
    recv(sockfd, header->data, header->data_size, 0);
    return header;
}

// ============================================================================
// SECTION 13: REAL-WORLD SCENARIO - NETWORK PACKET HANDLER
// ============================================================================

NetworkPacket *receive_packet_vulnerable(int sockfd) {
    NetworkPacket *packet = malloc(sizeof(NetworkPacket));
    if (!packet) return NULL;
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    packet->packet_size = read_uint32_from_network(sockfd);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    packet->chunk_count = read_uint32_from_network(sockfd);
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    packet->buffer = malloc(packet->packet_size);
    if (!packet->buffer) {
        free(packet);
        return NULL;
    }
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    recv(sockfd, packet->buffer, packet->packet_size, 0);
    return packet;
}

NetworkPacket *receive_packet_safe(int sockfd) {
    NetworkPacket *packet = malloc(sizeof(NetworkPacket));
    if (!packet) return NULL;
    
    packet->packet_size = read_uint32_from_network(sockfd);
    packet->chunk_count = read_uint32_from_network(sockfd);
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (packet->packet_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Packet too large\n");
        free(packet);
        return NULL;
    }
    
    packet->buffer = malloc(packet->packet_size);
    if (!packet->buffer) {
        free(packet);
        return NULL;
    }
    
    recv(sockfd, packet->buffer, packet->packet_size, 0);
    return packet;
}

// ============================================================================
// SECTION 14: REAL-WORLD SCENARIO - SESSION MANAGER
// ============================================================================

SessionManager *create_session_manager_vulnerable(uint32_t user_count, uint32_t session_size) {
    SessionManager *mgr = malloc(sizeof(SessionManager));
    if (!mgr) return NULL;
    
    mgr->user_count = user_count;
    mgr->session_size = session_size;
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    mgr->sessions = malloc(user_count * session_size);
    if (!mgr->sessions) {
        free(mgr);
        return NULL;
    }
    
    return mgr;
}

SessionManager *create_session_manager_safe(uint32_t user_count, uint32_t session_size) {
    SessionManager *mgr = malloc(sizeof(SessionManager));
    if (!mgr) return NULL;
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (user_count > MAX_USERS || session_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Invalid session parameters\n");
        free(mgr);
        return NULL;
    }
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (user_count > 0 && session_size > SIZE_MAX / user_count) {
        fprintf(stderr, "Overflow detected\n");
        free(mgr);
        return NULL;
    }
    
    mgr->user_count = user_count;
    mgr->session_size = session_size;
    mgr->sessions = malloc(user_count * session_size);
    if (!mgr->sessions) {
        free(mgr);
        return NULL;
    }
    
    return mgr;
}

// ============================================================================
// SECTION 15: REAL-WORLD SCENARIO - FILE PARSER
// ============================================================================

Collection *parse_collection_vulnerable(FILE *fp) {
    Collection *col = malloc(sizeof(Collection));
    if (!col) return NULL;
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    fread(&col->count, sizeof(col->count), 1, fp);
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    fread(&col->item_size, sizeof(col->item_size), 1, fp);
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    col->items = malloc(col->count * col->item_size);
    if (!col->items) {
        free(col);
        return NULL;
    }
    
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    fread(col->items, col->item_size, col->count, fp);
    return col;
}

Collection *parse_collection_safe(FILE *fp) {
    Collection *col = malloc(sizeof(Collection));
    if (!col) return NULL;
    
    fread(&col->count, sizeof(col->count), 1, fp);
    fread(&col->item_size, sizeof(col->item_size), 1, fp);
    
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (col->count > MAX_COUNT || col->item_size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Invalid collection parameters\n");
        free(col);
        return NULL;
    }
    
    col->items = malloc(col->count * col->item_size);
    if (!col->items) {
        free(col);
        return NULL;
    }
    
    fread(col->items, col->item_size, col->count, fp);
    return col;
}

// ============================================================================
// SECTION 16: EDGE CASES - ALLOCA AND STACK ALLOCATION
// ============================================================================

void test_alloca_vulnerable(size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *stack_buf = alloca(size);
    memset(stack_buf, 0, size);
}

void test_alloca_safe(size_t size) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    if (size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Stack allocation too large\n");
        return;
    }
    char *stack_buf = alloca(size);
    memset(stack_buf, 0, size);
}

void test_malloca_vulnerable(size_t size) {
    // ruleid: Memory-Allocation-with-Excessive-Size-Value
    char *buf = _malloca(size);
    if (buf) {
        memset(buf, 0, size);
        _freea(buf);
    }
}

// ============================================================================
// SECTION 17: EDGE CASES - CONST AND SIZEOF (SHOULD BE SAFE)
// ============================================================================

void test_const_size_safe() {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    char *buffer = malloc(1024);
    if (buffer) {
        memset(buffer, 0, 1024);
        free(buffer);
    }
}

void test_sizeof_safe(size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    int *array = malloc(count * sizeof(int));
    if (array) free(array);
}

void test_sizeof_calloc_safe(size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    int *array = calloc(count, sizeof(int));
    if (array) free(array);
}

void test_sizeof_realloc_safe(char *old_buffer, size_t count) {
    // ok: Memory-Allocation-with-Excessive-Size-Value
    char *new_buffer = realloc(old_buffer, count * sizeof(char));
    if (new_buffer) {
        memset(new_buffer, 0, count);
    }
}

// ============================================================================
// SECTION 18: MAIN ENTRY POINT
// ============================================================================

int main(int argc, char *argv[]) {
    printf("Memory Allocation with Excessive Size Value Test Suite\n");
    
    // Safe operations
    test_const_size_safe();
    test_sizeof_safe(100);
    test_sizeof_calloc_safe(100);
    test_argv_malloc_safe(argc, argv);
    test_argv_calloc_safe(argc, argv);
    
    // Vulnerable operations (only run with specific test flags)
    if (argc > 1 && strcmp(argv[1], "--test-vuln") == 0) {
        printf("Running vulnerable test cases...\n");
        
        test_argv_malloc_vulnerable(argc, argv);
        test_integer_overflow_multiply_vulnerable(1000, 1000);
        test_vla_stack_vulnerable(1024);
        test_missing_null_check_malloc_vulnerable(1024);
        test_missing_bounds_check_vulnerable(1024);
        
#ifdef __cplusplus
        test_cpp_new_array_vulnerable(1024);
#endif
    }
    
    printf("Test compilation successful\n");
    return 0;
}

// ============================================================================
// ADDITIONAL HELPERS FOR COMPILATION
// ============================================================================

static void *alloca(size_t size) {
    return malloc(size);
}

static void *_malloca(size_t size) {
    return malloc(size);
}

static void _freea(void *ptr) {
    free(ptr);
}

static int recv(int sockfd, void *buf, size_t len, int flags) {
    return 0;
}

static int fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return 0;
}

static void assert(int expr) {
    if (!expr) {
        fprintf(stderr, "Assertion failed\n");
        exit(1);
    }
}