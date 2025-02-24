/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.4 */

#ifndef PB_PORTNUMS_PB_H_INCLUDED
#define PB_PORTNUMS_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _PortNum {
    PortNum_UNKNOWN_APP = 0,
    PortNum_TEXT_MESSAGE_APP = 1,
    PortNum_REMOTE_HARDWARE_APP = 2,
    PortNum_POSITION_APP = 3,
    PortNum_NODEINFO_APP = 4,
    PortNum_ROUTING_APP = 5,
    PortNum_ADMIN_APP = 6,
    PortNum_REPLY_APP = 32,
    PortNum_IP_TUNNEL_APP = 33,
    PortNum_SERIAL_APP = 64,
    PortNum_STORE_FORWARD_APP = 65,
    PortNum_RANGE_TEST_APP = 66,
    PortNum_ENVIRONMENTAL_MEASUREMENT_APP = 67,
    PortNum_TUNNEL_APP= 268,
    PortNum_PRIVATE_APP = 256,
    PortNum_ATAK_FORWARDER = 257,
    PortNum_MAX = 511
} PortNum;

/* Helper constants for enums */
#define _PortNum_MIN PortNum_UNKNOWN_APP
#define _PortNum_MAX PortNum_MAX
#define _PortNum_ARRAYSIZE ((PortNum)(PortNum_MAX+1))


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
