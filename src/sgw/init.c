#define TRACE_MODULE _sgw_init

#include "core_debug.h"
#include "core_thread.h"

#include "context.h"
#include "event.h"

static thread_id sgw_sm_thread;
void *THREAD_FUNC sgw_sm_main(thread_id id, void *data);

status_t sgw_initialize()
{
    status_t rv;

    rv = sgw_ctx_init();
    if (rv != CORE_OK) return rv;

    rv = thread_create(&sgw_sm_thread, NULL, sgw_sm_main, NULL);
    if (rv != CORE_OK) return rv;

    return CORE_OK;
}

void sgw_terminate(void)
{
    thread_delete(sgw_sm_thread);

    sgw_ctx_final();
}

void *THREAD_FUNC sgw_sm_main(thread_id id, void *data)
{
    event_t event;
    sgw_sm_t sgw_sm;
    c_time_t prev_tm, now_tm;
    int r;

    memset(&event, 0, sizeof(event_t));

    sgw_self()->queue_id = event_create();
    d_assert(sgw_self()->queue_id, return NULL, 
            "SGW event queue creation failed");
    tm_service_init(&sgw_self()->tm_service);
    gtp_xact_init(&sgw_self()->gtp_xact_ctx, &sgw_self()->tm_service,
            EVT_TM_SGW_T3, 3000, 3); /* 3 sec, 3 retry-count */

    fsm_create(&sgw_sm.fsm, sgw_state_initial, sgw_state_final);
    d_assert(&sgw_sm.fsm, return NULL, "SGW state machine creation failed");
    fsm_init((fsm_t*)&sgw_sm, 0);

    prev_tm = time_now();

    while ((!thread_should_stop()))
    {
        r = event_timedrecv(sgw_self()->queue_id, &event, EVENT_WAIT_TIMEOUT);

        d_assert(r != CORE_ERROR, continue,
                "While receiving a event message, error occurs");

        now_tm = time_now();

        /* if the gap is over 10 ms, execute preriodic jobs */
        if (now_tm - prev_tm > EVENT_WAIT_TIMEOUT)
        {
            tm_execute_tm_service(
                    &sgw_self()->tm_service, sgw_self()->queue_id);

            prev_tm = now_tm;
        }

        if (r == CORE_TIMEUP)
        {
            continue;
        }

        fsm_dispatch((fsm_t*)&sgw_sm, (fsm_event_t*)&event);
    }

    fsm_final((fsm_t*)&sgw_sm, 0);
    fsm_clear((fsm_t*)&sgw_sm);

    gtp_xact_final();
    event_delete(sgw_self()->queue_id);

    return NULL;
}