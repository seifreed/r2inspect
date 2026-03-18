# Integration Testing Cleanup Candidates

These integration tests still look primarily historical by naming or intent and should be reviewed for split into:

- `tests/integration/product/` when they protect a user-visible workflow
- `tests/integration/historical/` when they only preserve coverage archaeology

First review candidates:

- `tests/integration/test_integration_phase2_batch_processing_bridge.py`
- `tests/integration/test_integration_phase2_batch_processing_edges_bridge.py`
- `tests/integration/test_phase2_pipeline.py`
- `tests/integration/test_pipeline_stages_real.py`
- `tests/integration/test_phase3_real_no_mocks_hashing_similarity_paths.py`
- `tests/integration/test_phase2_real_no_mocks_hashing_deep_paths.py`
- `tests/integration/test_hashing_and_function_analyzers_exhaustive_real.py`
- `tests/integration/test_analysis_pipeline_real.py`

Secondary candidates by historical naming:

- `tests/integration/test_integration_cli_main_validators_batch_output_gaps.py`
- `tests/integration/test_integration_top10_wave5_remaining_edges.py`
- `tests/integration/test_integration_top10_wave6_remaining_edges.py`
- `tests/integration/test_integration_top10_wave7_remaining_edges.py`
- `tests/integration/test_integration_top10_wave8_remaining_edges.py`
- `tests/integration/test_integration_top10_wave9_remaining_edges.py`
- `tests/integration/test_integration_top10_wave10_remaining_edges.py`

Goal:

- reduce accidental bridge/wave coverage
- keep only behavior-oriented integration tests in the main path
