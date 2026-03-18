# Integration Testing Deletion Candidates

These files are now the most likely deletion/archive candidates after behavior coverage already added in `tests/integration/product/`:

- `tests/integration/test_integration_targeted_module_coverage.py` removed
- `tests/integration/test_integration_targeted_small_gaps_core.py` removed
- `tests/integration/test_integration_cli_main_validators_batch_output_gaps.py` removed
- `tests/integration/test_integration_circuit_breaker_bridge.py` removed
- `tests/integration/test_integration_cli_retry_to_100.py` removed
- `tests/integration/test_integration_phase_cli_retry_100_bridge.py` removed
- `tests/integration/test_integration_cli_analyze_command_bridge.py` removed
- `tests/integration/test_integration_cli_batch_command_bridge.py` removed
- `tests/integration/test_integration_cli_commands_bridge.py` removed
- `tests/integration/test_integration_cli_config_bridge.py` removed
- `tests/integration/test_integration_cli_interactive_command_bridge.py` removed
- `tests/integration/test_integration_cli_display_metadata_bridge.py` removed
- `tests/integration/test_integration_cli_display_similarity_bridge.py` removed
- `tests/integration/test_integration_global_wave_remaining_bridge.py` removed
- `tests/integration/test_integration_global_wave2_remaining_bridge.py` removed
- `tests/integration/test_integration_global_next5_to_100_bridge.py` removed
- `tests/integration/test_integration_top10_to_100_bridge.py` removed
- `tests/integration/test_integration_global_final16_bridge.py` removed
- `tests/integration/test_integration_global_top10_to_100_bridge.py` removed
- `tests/integration/test_integration_top10_wave10_unique_bridge.py` removed
- `tests/integration/test_integration_top10_wave9_unique_bridge.py` removed
- `tests/integration/test_integration_top10_wave8_unique_bridge.py` removed
- `tests/integration/test_integration_top10_wave7_unique_bridge.py` removed
- `tests/integration/test_integration_top10_wave6_unique_bridge.py` removed
- `tests/integration/test_integration_phase5_wave_b_closeout.py` removed
- `tests/integration/test_integration_phase5_to_100_bridge.py` removed
- `tests/integration/test_integration_phase5_to_95_bridge.py` removed
- `tests/integration/test_integration_phase4_to_95_bridge.py` removed
- `tests/integration/test_integration_cluster_under90_next_wave_gaps.py` removed
- `tests/integration/test_integration_cluster_under90_next_wave.py` removed
- `tests/integration/test_integration_phase3_to_90_bridge.py` removed
- next likely numeric candidates:
  `tests/integration/test_integration_phase3_gap_high_missing_bridge.py`
  `tests/integration/test_integration_phase3_gap_core_bridge.py`
  `tests/integration/test_integration_phase2_authenticode_bridge.py`

Already removed after behavior coverage replacement:

- `tests/integration/historical/test_phase2_pipeline.py`
- `tests/integration/historical/test_pipeline_stages_real.py`
- `tests/integration/historical/test_analysis_pipeline_real.py`
- `tests/integration/historical/test_phase2_real_no_mocks_hashing_deep_paths.py`
- `tests/integration/historical/test_phase3_real_no_mocks_hashing_similarity_paths.py`
- `tests/integration/historical/test_integration_top10_wave3_remaining_edges.py`
- `tests/integration/historical/test_integration_top10_wave4_remaining_edges.py`
- `tests/integration/test_integration_targeted_module_coverage.py`
- `tests/integration/test_integration_targeted_small_gaps_core.py`
- `tests/integration/test_integration_cli_main_validators_batch_output_gaps.py`
- `tests/integration/test_integration_circuit_breaker_bridge.py`
- `tests/integration/test_integration_cli_retry_to_100.py`
- `tests/integration/test_integration_phase_cli_retry_100_bridge.py`
- `tests/integration/test_integration_cli_analyze_command_bridge.py`
- `tests/integration/test_integration_cli_batch_command_bridge.py`
- `tests/integration/test_integration_cli_commands_bridge.py`
- `tests/integration/test_integration_cli_config_bridge.py`
- `tests/integration/test_integration_cli_interactive_command_bridge.py`
- `tests/integration/test_integration_cli_display_metadata_bridge.py`
- `tests/integration/test_integration_cli_display_similarity_bridge.py`
- `tests/integration/test_integration_global_wave_remaining_bridge.py`
- `tests/integration/test_integration_global_wave2_remaining_bridge.py`
- `tests/integration/test_integration_global_next5_to_100_bridge.py`
- `tests/integration/test_integration_top10_to_100_bridge.py`
- `tests/integration/test_integration_global_final16_bridge.py`
- `tests/integration/test_integration_global_top10_to_100_bridge.py`
- `tests/integration/test_integration_top10_wave10_unique_bridge.py`
- `tests/integration/test_integration_top10_wave9_unique_bridge.py`
- `tests/integration/test_integration_top10_wave8_unique_bridge.py`
- `tests/integration/test_integration_top10_wave7_unique_bridge.py`
- `tests/integration/test_integration_top10_wave6_unique_bridge.py`
- `tests/integration/test_integration_top10_wave5_unique_bridge.py`
- `tests/integration/test_integration_top10_wave6_remaining_edges.py`
- `tests/integration/test_integration_top10_wave5_remaining_edges.py`
- `tests/integration/test_integration_top10_wave4_unique_bridge.py`
- `tests/integration/test_integration_top10_wave3_unique_bridge.py`
- `tests/integration/test_integration_phase5_wave_b_closeout.py`
- `tests/integration/test_integration_phase5_to_100_bridge.py`
- `tests/integration/test_integration_phase5_to_95_bridge.py`
- `tests/integration/test_integration_phase4_to_95_bridge.py`
- `tests/integration/test_integration_cluster_under90_next_wave_gaps.py`
- `tests/integration/test_integration_cluster_under90_next_wave.py`
- `tests/integration/test_integration_phase3_to_90_bridge.py`
