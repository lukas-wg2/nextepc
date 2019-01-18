#include "core_debug.h"
#include "core_pkbuf.h"
#include "core_lib.h"
#include "3gpp_types.h"
#include <mongoc.h>
#include <freeDiameter/extension.h>
#include <signal.h>
#include <time.h>
#include "core_debug.h"
#include "core_pool.h"
#include "core_lib.h"
#include "core_network.h"
#include "3gpp_types.h"

#include "gtp/gtp_xact.h"

#include "fd/fd_lib.h"
#include "fd/rx/rx_dict.h"
#include "fd/rx/rx_message.h"

#include "pcscf_fd_path_pcrf_load_test.h"

#include "fd/fd_lib.h"
#include "fd/gx/gx_dict.h"
#include "fd/gx/gx_message.h"

#include "common/context.h"

#include "testutil.h"

#define AUTH_APP_ID 16777238
#define VENDOR_ID_3GPP 10415
#define SENT_AAR 1

struct dict_object *ccr_cmd = NULL;
struct dict_object *cca_cmd = NULL;
struct dict_object *dataobj_re_auth_request_type = NULL;
struct dict_object *origin_host = NULL;
struct dict_object *origin_realm = NULL;
struct dict_object *dest_host = NULL;
struct dict_object *dest_realm = NULL;
struct dict_object *reauth_cmd = NULL;
struct dict_object *auth_app_id = NULL;
struct dict_object *service_cxt_id = NULL;
struct dict_object *cc_req_type = NULL;
struct dict_object *cc_req_num = NULL;
struct dict_object *bearer_usage = NULL;
struct dict_object *pflt_oper = NULL;
struct dict_object *pflt_info = NULL;
struct dict_object *pflt_id = NULL;
struct dict_object *gx_inf;
struct dict_object *term_cause = NULL;

c_uint8_t *rx_sid = 0;

static int app_gx_entry()
{
    {
        application_id_t dcca_id = AUTH_APP_ID;
        application_id_t ccr_id = 272;
        application_id_t cca_id = 272;
        application_id_t reauth_id = 258;
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_APPLICATION, APPLICATION_BY_ID, &dcca_id, &gx_inf, ENOENT));
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R, &ccr_id, &ccr_cmd, ENOENT));
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_A, &cca_id, &cca_cmd, ENOENT));
    }

    /* Applications section */
#if 0
   
#endif

    // Do registeration and init stuff
    {
        struct disp_when data;

        TRACE_DEBUG(FULL, "Initializing dispatch callbacks for Gx interface");

        memset(&data, 0, sizeof(data));
        data.app = gx_inf;
        data.command = ccr_cmd;

        memset(&data, 0, sizeof(data));
        data.app = gx_inf;
        data.command = cca_cmd;

#ifdef REAUTH
        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_NAME,
                                 "Re-Auth-Request", &reauth_cmd, ENOENT));
        memset(&data, 0, sizeof(data));
        data.app = gx_inf;
        data.command = reauth_cmd;
        printf("register REAUTH\n");
#endif
    }

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP, AVP_BY_NAME,
                             "Origin-Host",
                             &origin_host,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Origin-Realm",
                             &origin_realm,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Destination-Host",
                             &dest_host,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Destination-Realm",
                             &dest_realm,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Auth-Application-Id",
                             &auth_app_id,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Service-Context-Id",
                             &service_cxt_id,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "CC-Request-Type",
                             &cc_req_type,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "Termination-Cause",
                             &term_cause,
                             ENOENT));

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                             DICT_AVP,
                             AVP_BY_NAME,
                             "CC-Request-Number",
                             &cc_req_num,
                             ENOENT));
    {
        struct dict_avp_request req = {VENDOR_ID_3GPP, 0, "Bearer-Usage"};

        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                                 DICT_AVP,
                                 AVP_BY_NAME_AND_VENDOR,
                                 &req,
                                 &bearer_usage,
                                 ENOENT));
    }
    {
        struct dict_avp_request req = {VENDOR_ID_3GPP, 0, "Packet-Filter-Operation"};

        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                                 DICT_AVP,
                                 AVP_BY_NAME_AND_VENDOR,
                                 &req,
                                 &pflt_oper,
                                 ENOENT));
    }
    {
        struct dict_avp_request req = {VENDOR_ID_3GPP, 0, "Packet-Filter-Information"};

        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                                 DICT_AVP,
                                 AVP_BY_NAME_AND_VENDOR,
                                 &req,
                                 &pflt_info,
                                 ENOENT));
    }
    {
        struct dict_avp_request req = {VENDOR_ID_3GPP, 0, "Packet-Filter-Identifier"};

        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict,
                                 DICT_AVP,
                                 AVP_BY_NAME_AND_VENDOR,
                                 &req,
                                 &pflt_id,
                                 ENOENT));
    }

    TRACE_DEBUG(INFO, "Extension 'Gx' initialized");
    return 0;
}

int send_ccr_msg()
{
    struct dict_object *cmd_r = NULL;
    application_id_t ccr_id = 272;
    struct msg *req = NULL;
    struct avp *avp = NULL;
    struct avp *avpch1, *avpch2;
    union avp_value val;
    struct ta_mess_info *mi = NULL, *svg;
    struct session *sess = NULL;

    CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_COMMAND, CMD_BY_CODE_R, &ccr_id, &cmd_r, ENOENT));

    TRACE_DEBUG(FULL, "Creating a new CCR message for sending.");

    /* Create the request from template */
    CHECK_FCT_DO(fd_msg_new(cmd_r, MSGFL_ALLOC_ETEID, &req), goto out);

    /* Create a new session */
    CHECK_FCT_DO(fd_sess_new(&sess,
                             fd_g_config->cnf_diamid,
                             fd_g_config->cnf_diamid_len,
                             (unsigned char *)"CCR_SESSION", strlen("CCR_SESSION")),
                 goto out);

    printf("new session %p \n", sess);
    //Hold the session till terminate happens
    CHECK_FCT(fd_sess_ref_msg(sess));

    /* Session-Id */
    {
        os0_t sid;
        size_t sidlen;
        struct dict_object *sess_id = NULL;

        CHECK_FCT(fd_dict_search(fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &sess_id, ENOENT));

        CHECK_FCT_DO(fd_sess_getsid(sess, &sid, &sidlen), goto out);
        CHECK_FCT_DO(fd_msg_avp_new(sess_id, 0, &avp), goto out);
        val.os.data = sid;
        val.os.len = sidlen;
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_FIRST_CHILD, avp), goto out);
    }

    /* Set the Destination-Realm AVP */
    {
        CHECK_FCT_DO(fd_msg_avp_new(fd_destination_realm, 0, &avp), goto out);
        val.os.data = (unsigned char *)("006.240.3gppnetwork.org");
        val.os.len = strlen("006.240.3gppnetwork.org");
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /* Set the Destination-Host AVP if needed*/
    {
        CHECK_FCT_DO(fd_msg_avp_new(fd_destination_host, 0, &avp), goto out);
        val.os.data = (unsigned char *)("pcrf.mnc006.mcc240.3gppnetwork.org");
        val.os.len = strlen("pcrf.mnc006.mcc240.3gppnetwork.org");
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /* Set Origin-Host & Origin-Realm */
    CHECK_FCT_DO(fd_msg_add_origin(req, 0), goto out);

    /*  Set Auth-Application ID */
    {
        CHECK_FCT_DO(fd_msg_avp_new(fd_auth_application_id, 0, &avp), goto out);
        val.i32 = 16777238; // Auth-App id is 4 for CCR
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /*     Set Service Context ID     */
    {

        CHECK_FCT_DO(fd_msg_avp_new(service_cxt_id, 0, &avp), goto out);
        val.os.data = (unsigned char *)("test@tst");
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /*     Set Request Type	      */
    {
#define CCR_INIT_REQUEST 1
#define CCR_UPDATE_REQUEST 2
#define CCR_TERMINATION_REQUEST 3
#define CCR_EVENT_REQUEST 4

        CHECK_FCT_DO(fd_msg_avp_new(cc_req_type, 0, &avp), goto out);
        val.i32 = CCR_INIT_REQUEST;

        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /*     Set Request Number	      */
    {
        CHECK_FCT_DO(fd_msg_avp_new(cc_req_num, 0, &avp), goto out);
        val.i32 = 1;
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    {
        //Set Bearer-Usage
        CHECK_FCT_DO(fd_msg_avp_new(bearer_usage, 0, &avp), goto out);
        val.i32 = 1; //IMS
        CHECK_FCT_DO(fd_msg_avp_setvalue(avp, &val), goto out);
        CHECK_FCT_DO(fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp), goto out);
    }

    /* Set Subscription-Id */
    {
        fd_msg_avp_new(gx_subscription_id, 0, &avp);
        {
            fd_msg_avp_new(gx_subscription_id_type, 0, &avpch1);
            val.i32 = GX_SUBSCRIPTION_ID_TYPE_END_USER_IMSI;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        {
            fd_msg_avp_new(gx_subscription_id_data, 0, &avpch1);
            val.os.data = (c_uint8_t *)"240064000003490";
            val.os.len = strlen("240064000003490");
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    {
        /* Set Called-Station-Id */
        fd_msg_avp_new(gx_called_station_id, 0, &avp);
        val.os.data = (c_uint8_t *)"ims";
        val.os.len = strlen("ims");
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    /* Set QoS-Information */
    {
        fd_msg_avp_new(gx_qos_information, 0, &avp);
        {
            fd_msg_avp_new(gx_apn_aggregate_max_bitrate_ul, 0, &avpch1);
            val.u32 = 0x00F00000;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        {
            fd_msg_avp_new(gx_apn_aggregate_max_bitrate_dl, 0, &avpch1);
            val.u32 = 0x02300000;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    /* Set Framed-IP-Address */
    {
        fd_msg_avp_new(gx_framed_ip_address, 0, &avp);
        val.os.data = (c_uint8_t *)"\x2d\x2d\x00\x03"; //45.45.0.3
        val.os.len = 4;
        fd_msg_avp_setvalue(avp, &val);
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    /* Set Default-EPS-Bearer-QoS */
    {
        fd_msg_avp_new(gx_default_eps_bearer_qos, 0, &avp);
        {
            fd_msg_avp_new(gx_qos_class_identifier, 0, &avpch1);
            val.u32 = 0x00000006;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        {
            fd_msg_avp_new(gx_allocation_retention_priority, 0, &avpch1);
            {
                fd_msg_avp_new(gx_priority_level, 0, &avpch2);
                val.u32 = 0x00000006;
                fd_msg_avp_setvalue(avpch2, &val);
                fd_msg_avp_add(avpch1, MSG_BRW_LAST_CHILD, avpch2);
            }
            {
                fd_msg_avp_new(gx_pre_emption_capability, 0, &avpch2);
                val.u32 = 0x00000001;
                fd_msg_avp_setvalue(avpch2, &val);
                fd_msg_avp_add(avpch1, MSG_BRW_LAST_CHILD, avpch2);
            }
            {
                fd_msg_avp_new(gx_pre_emption_vulnerability, 0, &avpch2);
                val.u32 = 0x00000001;
                fd_msg_avp_setvalue(avpch2, &val);
                fd_msg_avp_add(avpch1, MSG_BRW_LAST_CHILD, avpch2);
            }
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    /* Set Supported Features */
    {
        fd_msg_avp_new(gx_supported_features, 0, &avp);
        {
            fd_msg_avp_new(gx_feature_list_id, 0, &avpch1);
            val.i32 = 1;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        {
            fd_msg_avp_new(gx_feature_list, 0, &avpch1);
            val.u32 = 0x0000000b;
            fd_msg_avp_setvalue(avpch1, &val);
            fd_msg_avp_add(avp, MSG_BRW_LAST_CHILD, avpch1);
        }
        fd_msg_avp_add(req, MSG_BRW_LAST_CHILD, avp);
    }

    fflush(stderr);

    /* Send the request */
    printf("CCA %p\n", req);
    // Everthing Done. Store the state: reply should retreive it
    CHECK_FCT(fd_msg_send(&req, NULL, NULL));

out:
    return 0;
}

static void pcrf_test(abts_case *tc, void *data)
{

    /* Create and send CC-request */
    pcscf_fd_init_load_test();
    core_sleep(time_from_msec(2000));
    printf("test sending CCR \n");
    app_gx_entry();
    core_sleep(time_from_msec(2000));
    send_ccr_msg();


    /* Send AA-Request */
    int i, j = SENT_AAR;
    printf("sending %d AAR \n", j);
    for (i = 0; i < j; i++)
    {
        rx_sid = 0;
        pcscf_rx_send_aar_load_test(&rx_sid, "45.45.0.3", 1, 1, i);
        pkbuf_show();
    }

    core_sleep(time_from_msec(2000));
}

abts_suite *test_pcrf(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

        abts_run_test(suite, pcrf_test, NULL);

    return suite;
}
