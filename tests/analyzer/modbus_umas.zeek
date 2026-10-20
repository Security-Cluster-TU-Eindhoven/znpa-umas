# @TEST-EXEC: zeek -C -r ${TRACES}/modbus_umas.pcap $PACKAGE %INPUT
# @TEST-EXEC: btest-diff modbus_umas.log
# @TEST-EXEC: btest-diff modbus.log
#
# @TEST-DOC: Test MODBUS UMAS analyzer extensions with small trace.