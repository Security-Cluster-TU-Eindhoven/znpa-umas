# @TEST-EXEC: zeek -C -r ${TRACES}/umas_segmentation.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff modbus_umas.log
#
# @TEST-DOC: UMAS PDUs pipelined in one segment, split across segments, mixed with other Modbus PDUs, and with unknown function codes.
