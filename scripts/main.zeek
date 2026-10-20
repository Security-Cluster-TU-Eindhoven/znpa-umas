# Copyright (c) 2025-2026, Eindhoven University of Technology
# SPDX-License-Identifier: BSD-3-Clause

##! Logs Schneider Electric UMAS (Modbus function code 90) messages to
##! modbus_umas.log.
##!
##! Zeek's Modbus analyzer does not expose the payload of function code 90,
##! so this script reads the raw TCP stream through tcp_contents, frames
##! Modbus/TCP ADUs using the MBAP length field and remembers the UMAS
##! session key and function code of each ADU by transaction identifier.
##! The record is written when Zeek's analyzer raises modbus_message for the
##! same ADU, so that timestamps and connection data match modbus.log.

@load base/protocols/modbus
@load ./consts

module Modbus_Umas;

export {
    redef enum  Log::ID += {LOG_UMAS};

    type Umas_Record: record {
        ts                      : time              &log;             # Timestamp of event
        uid                     : string            &log;             # Zeek unique ID for connection
        id                      : conn_id           &log;             # Zeek connection struct (addresses and ports)
        is_orig                 : bool              &log;             # the message came from the originator/client or the responder/server
        tid                     : count             &log &optional;   # Modbus transaction id
        unit                    : count             &log &optional;   # Modbus terminal unit identifier
        func                    : string            &log &optional;   # Modbus Function
        request_response        : string            &log &optional;   # REQUEST or RESPONSE
        umas_func               : string            &log &optional;   # UMAS function
        session_key             : count             &log &optional;   # UMAS session key
    };
    global log_modbus_umas: event(rec: Umas_Record);

    ## Maximum number of parsed UMAS ADUs kept per direction while waiting
    ## for the matching modbus_message event.
    const max_pending = 100 &redef;
}

redef tcp_content_delivery_ports_orig += {
    [502/tcp] = T
};

redef tcp_content_delivery_ports_resp += {
    [502/tcp] = T
};

# UMAS fields extracted from the raw stream for a single ADU.
type Umas_Pdu: record {
    session_key             : count;
    umas_func               : count;
};

# Stream reassembly state for one direction of a connection.
type Umas_Flow: record {
    buf                     : string                    &default="";  # bytes of an incomplete ADU header
    skip                    : count                     &default=0;   # remaining body bytes of the current ADU
    pending                 : table[count] of Umas_Pdu;               # parsed ADUs, indexed by transaction id
};

type Umas_State: record {
    orig                    : Umas_Flow;
    resp                    : Umas_Flow;
};

redef record connection += {
    umas: Umas_State &optional;
};

function get_flow(c: connection, is_orig: bool): Umas_Flow {
    if ( ! c?$umas )
        c$umas = Umas_State($orig=Umas_Flow(), $resp=Umas_Flow());

    return is_orig ? c$umas$orig : c$umas$resp;
}

# Consumes stream data, parsing every complete MBAP header followed by the
# UMAS session key and function code. Only the first 10 bytes of each ADU are
# needed, the rest of its body is skipped.
function parse_stream(flow: Umas_Flow, contents: string) {
    local data = flow$buf + contents;

    if ( flow$skip > 0 ) {
        if ( |data| <= flow$skip ) {
            flow$skip -= |data|;
            flow$buf = "";
            return;
        }
        data = data[flow$skip:];
        flow$skip = 0;
    }

    while ( |data| >= 7 ) {
        local len = bytestring_to_count(data[4:6]);
        local adu_len = 6 + len;

        if ( |data| < adu_len && |data| < 10 )
            break;

        if ( len >= 4 &&
             bytestring_to_count(data[2:4]) == 0 &&
             bytestring_to_count(data[7]) == 90 ) {
            if ( |flow$pending| >= max_pending )
                clear_table(flow$pending);

            flow$pending[bytestring_to_count(data[0:2])] = Umas_Pdu(
                $session_key=bytestring_to_count(data[8]),
                $umas_func=bytestring_to_count(data[9]));
        }

        if ( |data| < adu_len ) {
            flow$skip = adu_len - |data|;
            data = "";
            break;
        }

        data = data[adu_len:];
    }

    flow$buf = data;
}

event zeek_init() &priority=5 {
    Log::create_stream(Modbus_Umas::LOG_UMAS, [$columns=Umas_Record, $ev=log_modbus_umas, $path="modbus_umas"]);
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string) {
    parse_stream(get_flow(c, is_orig), contents);
}

# After a gap the stream position of ADU boundaries is unknown, so reset it.
event content_gap(c: connection, is_orig: bool, seq: count, length: count) {
    if ( ! c?$umas )
        return;

    local flow = get_flow(c, is_orig);
    flow$buf = "";
    flow$skip = 0;
    clear_table(flow$pending);
}

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) {
    if ( headers$function_code != 90 || ! c?$umas )
        return;

    local flow = get_flow(c, is_orig);

    if ( headers$tid !in flow$pending )
        return;

    local pdu = flow$pending[headers$tid];
    delete flow$pending[headers$tid];

    local rec = Umas_Record($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig);
    rec$tid                 = headers$tid;
    rec$unit                = headers$uid;
    rec$func                = Modbus::function_codes[headers$function_code];
    rec$request_response    = is_orig ? "REQUEST" : "RESPONSE";
    rec$umas_func           = umas_func_codes[pdu$umas_func];
    rec$session_key         = pdu$session_key;

    Log::write(LOG_UMAS, rec);
}
