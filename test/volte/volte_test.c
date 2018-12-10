
#include "core_debug.h"
#include "core_pkbuf.h"
#include "core_lib.h"
#include "3gpp_types.h"
#include <mongoc.h>

#include "s1ap/s1ap_message.h"

#include "common/context.h"

#include "testutil.h"
#include "testpacket.h"

#include "pcscf_fd_path.h"

static void volte_test1(abts_case *tc, void *data)
{
  c_uint8_t *rx_sid = NULL;
  ///ccr request
  /* Send AA-Request without Flow */
  pcscf_rx_send_aar(&rx_sid, "45.45.0.3", 2, 1);
}

abts_suite *test_volte(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, volte_test1, NULL);

    return suite;
}
