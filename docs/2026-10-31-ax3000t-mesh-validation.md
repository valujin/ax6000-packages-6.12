# AX3000T MediaTek mesh port validation

The stock-layout Xiaomi AX3000T uses the MT7981 profile and two MT7981 DAT files. The runtime checks the board, l1profile chip and DAT paths, and UCI radio names before enrollment. Existing AX6000 board support and its distinct MT7986 profile remain present. Mesh starts disabled. The packet-tested managed guest capability is still limited to AX6000.

Host regression commands used in this workspace (the native staging directory supplies jshn and libraries):

```sh
export PYTHONPATH=tests
export MESH_TEST_NATIVE=/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/local-native-mesh-20261027/work/build/source/staging_dir/host
export MESH_TEST_UCI=/tmp/mesh-materialize-uci-build/uci
export UCODE=/tmp/mesh-ucode-build/ucode
python3 -m unittest test_mesh_radio_tuning test_mesh_radio_ready test_mesh_restart test_mesh_rpc
python3 -m unittest test_mesh_rpc
python3 -m unittest test_mesh_ax3000_uci
python3 -m unittest tests.test_mesh_transaction
```

The first aggregate passed 50 tests, the updated RPC fixture passed 9 tests, and the transaction suite passed 30 tests. AX3000T tests use real UCI and the actual hardware selector for controller enrollment and disable, DAT snapshot and rollback. The radio-tuning suite uses real UCI with an AX3000T profile and exercises bounded MU adoption, ownership checks and rollback. These are isolated host fixtures; they do not establish radio operation or interoperability on physical devices.

Additional AX3000T agent-role checks passed for both wired and wireless apply/disable, using real UCI and the actual MT7981 selector. They verify saved role/backhaul, original DAT snapshot and complete configuration/DAT restoration:

```sh
PYTHONPATH=tests MESH_TEST_UCI=/tmp/mesh-materialize-uci-build/uci python3 -m unittest \
  test_mesh_ax3000_uci.AX3000TRealEnrollment.test_real_uci_agent_wired \
  test_mesh_ax3000_uci.AX3000TRealEnrollment.test_real_uci_agent_wireless
```
