#ifndef SYSTEM_SECURITY_TRUSTED_T_H__
#define SYSTEM_SECURITY_TRUSTED_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int esv_init(const char* sealed_data_file);
int esv_seal_keys(const char* sealed_data_file);
int esv_sign(const char* message, void* signature, size_t sig_len);
int esv_verify(const char* message, void* signature, size_t sig_len);
int esv_close(void);

sgx_status_t SGX_CDECL esv_write_data(const char* file_name, const unsigned char* p_data, size_t len);
sgx_status_t SGX_CDECL esv_read_data(const char* file_name, unsigned char** pp_data, size_t* len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
