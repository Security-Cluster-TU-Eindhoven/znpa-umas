# Copyright (c) 2025-2026, Eindhoven University of Technology
# SPDX-License-Identifier: BSD-3-Clause

module Modbus_Umas;

export {
    const umas_func_codes = {
        [0x01] = "QUERY_GET_COM_INFO",          # Initialize a UMAS communication
        [0x02] = "GET_PLC_INFO",                # Request a PLC ID
        [0x03] = "READ_PROJECT_INFO",           # Read Project Information
        [0x04] = "GET_PLC_STATUS",              # Get internal PLC Info
        [0x06] = "GET_MEMORY_CARD_INFO",        # Get internal PLC SD-Card Info
        [0x0A] = "ECHO",                        # Sends back data sent to the PLC (used for synchronization)
        [0x10] = "TAKE_PLC_RESERVATION",        # Assign an "owner" to the PLC
        [0x11] = "RELEASE_PLC_RESERVATION",     # Release the reservation of a PLC
        [0x12] = "KEEP_PLC_RESERVATION_ALIVE",  # Keep alive message (???)
        [0x20] = "READ_MEMORY_BLOCK",           # Read a memory block of the PLC
        [0x21] = "WRITE_MEMORY_BLOCK",          # Write a memory block of the PLC
        [0x22] = "READ_VARIABLES",              # Read System bits, System Words and Strategy variables
        [0x23] = "WRITE_VARIABLES",             # Write System bits, System Words and Strategy variables
        [0x24] = "READ_COILS_REGISTERS",        # Read coils and holding registers from PLC
        [0x25] = "WRITE_COILS_REGISTERS",       # Write coils and holding registers into PLC
        [0x30] = "INITIALIZE_DOWNLOAD",         # Initialize Strategy download (copy from engineering PC to PLC)
        [0x31] = "DOWNLOAD_BLOCK",              # Download (copy from engineering PC to PLC) a strategy block to the PLC
        [0x32] = "END_STRATEGY_DOWNLOAD",       # Finish Strategy download (copy from engineering PC to PLC)
        [0x33] = "INITIALIZE_UPLOAD",           # Initialize Strategy upload (copy from PLC to engineering PC)
        [0x34] = "UPLOAD_BLOCK",                # Upload (copy from PLC to engineering PC) a strategy block
        [0x35] = "END_STRATEGY_UPLOAD",         # Finish strategy upload (copy from PLC to engineering PC)
        [0x39] = "READ_ETH_MASTER_DATA",        # Read Ethernet Master Data
        [0x40] = "START_TASK",                  # Starts a PLC task
        [0x41] = "STOP_TASK",                   # Stops a PLC task
        [0x50] = "CSA_REQUESTS",                # Manipulate PLC memory
        [0x58] = "CHECK_PLC",                   # Check PLC Connection status
        [0x70] = "READ_IO_OBJECT",              # Read IO Object
        [0x71] = "WRITE_IO_OBJECT",             # WriteIO Object
        [0x73] = "GET_STATUS_MODULE",           # Get Status Module
        [0xFD] = "RES_ERR",                     # Error response
        [0xFE] = "RES_OK",                      # OK response
    } &default=function(i: count):string { return fmt("unknown-%d", i); } &redef;
}
