#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../ocall_types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINTLN_STRING_DEFINED__
#define OCALL_PRINTLN_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_println_string, (const char* str));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_PRINT_ERROR_DEFINED__
#define OCALL_PRINT_ERROR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_error, (const char* str));
#endif
#ifndef OCALL_LSTAT_DEFINED__
#define OCALL_LSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lstat, (const char* path, struct stat* buf, size_t size));
#endif
#ifndef OCALL_STAT_DEFINED__
#define OCALL_STAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_stat, (const char* path, struct stat* buf, size_t size));
#endif
#ifndef OCALL_FSTAT_DEFINED__
#define OCALL_FSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fstat, (int fd, struct stat* buf, size_t size));
#endif
#ifndef OCALL_FTRUNCATE_DEFINED__
#define OCALL_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_ftruncate, (int fd, off_t length));
#endif
#ifndef OCALL_GETCWD_DEFINED__
#define OCALL_GETCWD_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getcwd, (char* buf, size_t size));
#endif
#ifndef OCALL_GETPID_DEFINED__
#define OCALL_GETPID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getpid, (void));
#endif
#ifndef OCALL_GETUID_DEFINED__
#define OCALL_GETUID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getuid, (void));
#endif
#ifndef OCALL_GETENV_DEFINED__
#define OCALL_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_getenv, (const char* name));
#endif
#ifndef OCALL_OPEN64_DEFINED__
#define OCALL_OPEN64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_open64, (const char* filename, int flags, mode_t mode));
#endif
#ifndef OCALL_CLOSE_DEFINED__
#define OCALL_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_close, (int fd));
#endif
#ifndef OCALL_LSEEK64_DEFINED__
#define OCALL_LSEEK64_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_lseek64, (int fd, off_t offset, int whence));
#endif
#ifndef OCALL_READ_DEFINED__
#define OCALL_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_read, (int fd, void* buf, size_t count));
#endif
#ifndef OCALL_WRITE_DEFINED__
#define OCALL_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write, (int fd, const void* buf, size_t count));
#endif
#ifndef OCALL_FSYNC_DEFINED__
#define OCALL_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fsync, (int fd));
#endif
#ifndef OCALL_FCNTL_DEFINED__
#define OCALL_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_fcntl, (int fd, int cmd, void* arg, size_t size));
#endif
#ifndef OCALL_UNLINK_DEFINED__
#define OCALL_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_unlink, (const char* pathname));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_encrypt(sgx_enclave_id_t eid);
sgx_status_t ecall_opendb(sgx_enclave_id_t eid, const char* dbname);
sgx_status_t ecall_execute_sql(sgx_enclave_id_t eid, const char* sql);
sgx_status_t ecall_closedb(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
