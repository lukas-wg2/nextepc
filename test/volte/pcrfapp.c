#define TRACE_MODULE _pcrfapp

#include "core_general.h"
#include "core_debug.h"
#include "core_semaphore.h"

#include "common/context.h"
#include "common/application.h"

#include "app_init.h"

static semaphore_id pcrf_sem1 = 0;
static semaphore_id pcrf_sem2 = 0;

status_t pcrf_app_initialize(
    const char *config_path, const char *log_path, const char *pid_path)
{
    pid_t pid;
    status_t rv;
    int app = 0;

    rv = app_will_initialize(config_path, log_path);
    if (rv != CORE_OK)
        return rv;

    app = context_self()->logger.trace.app;
    if (app)
    {
        d_trace_level(&_pcrfapp, app);
    }
    d_trace(1, "PCRF try to initialize\n");
    rv = pcrf_initialize();
    d_assert(rv == CORE_OK, , "Failed to intialize PCRF");
    d_trace(1, "PCRF initialize...done\n");
#if 0
  
#endif
    return CORE_OK;;
}

void test_app_terminate(void)
{
    app_will_terminate();

    /* if (context_self()->parameter.no_mme == 0) */

    if (context_self()->parameter.no_pcrf == 0)
    {
        if (pcrf_sem2)
            semaphore_post(pcrf_sem2);
        if (pcrf_sem1)
            semaphore_wait(pcrf_sem1);
    }
    if (pcrf_sem1)
        semaphore_delete(pcrf_sem1);
    if (pcrf_sem2)
        semaphore_delete(pcrf_sem2);

    app_did_terminate();
}
