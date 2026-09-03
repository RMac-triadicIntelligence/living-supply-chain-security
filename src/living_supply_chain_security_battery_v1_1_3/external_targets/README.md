# External target adapters

The battery is self-contained and tests an independent reference implementation.
For differential cold-fence runs, place historical artifacts here or point an adapter
at them without modifying their source. Intended targets include:

- `minato_garde.py`
- `minato_garde_v3.py`
- `authority_kernel_v8_1_fixed.py`
- `grace_basin_sim_v062_integrated.py`

Historical artifact findings are not silently counted as reference-implementation
passes. A harness can pass while the artifact under attack remains RED.
