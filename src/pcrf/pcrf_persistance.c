#include "core_lib.h"
#include "core_list.h"
#include "time.h"

#include "pcrf_gx_path.c"

static void get_gx_state(struct sess_state *sess_data)
{
    d_assert(sess_data, return,);

    sess_data->sid = (os0_t) "pcrf.open-ims.test;1547586413;1;CCR_SESSION";
        //sid
    sess_data->cc_request_type = (c_uint32_t) 1;
    
    sess_data->peer_host = (os0_t) "pcrf.open-ims.test";
        //peer-host
    sess_data->imsi_bcd = "ims";
        //imsi_bcd
    sess_data->apn = "ims";
        //apn
    sess_data->ipv4 = (c_uint8_t) 1;
        //ipv4
    sess_data->ipv6 = (c_uint8_t) 0;
        //ipv6
    sess_data->reserved = (c_uint8_t) 0;
        //ipv6
    sess_data->addr = (c_uint32_t) 50343213;
    c_uint8_t ipv6addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(sess_data->addr6, ipv6addr, IPV6_LEN);

    sess_data->ts.tv_sec = (__kernel_time_t) 0;
    sess_data->ts.tv_nsec = (long) 0;
}