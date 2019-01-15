#ifndef __PCSCF_FD_PATH_PCRF_LOAD_TEST_H__
#define __PCSCF_FD_PATH_PCRF_LOAD_TEST_H__

#include "core_errno.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

CORE_DECLARE(status_t) pcscf_fd_init_load_test(void);
CORE_DECLARE(void) pcscf_fd_final_load_test(void);

CORE_DECLARE(void) pcscf_rx_send_aar_load_test(c_uint8_t **rx_sid, const char *ip,
        int qos_type, int flow_presence, int session_id_opt);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PCSCF_FD_PATH_H__ */

