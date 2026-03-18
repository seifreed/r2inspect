# Testing Cleanup Candidates

Current likely archive/delete candidates once equivalent product behavior coverage is considered sufficient:

- highest-value unit baseline candidates right now:
- `tests/unit/test_misc_analyzers_wave3.py` removed
- `tests/unit/test_adapters_wave3.py` removed
- `tests/unit/test_analyzers_core_wave3.py` removed
- `tests/unit/test_analyzer_modules_coverage.py` removed
- `tests/unit/test_analyzers_final_coverage.py` removed
- `tests/unit/test_analyzers_method_walk_block386.py` removed
- `tests/unit/test_cli_main_block232.py` removed
- `tests/unit/test_analysis_runner_status_block152.py` removed
- `tests/unit/test_abstractions_base_analyzer_block222.py` removed
- `tests/unit/test_analysis_runner_helpers_block129.py` removed
- `tests/unit/test_adapter_validation_address_size_block123.py` removed
- `tests/unit/test_analysis_runner_block50.py` removed
- `tests/unit/test_adapter_validation_block18.py` removed
- `tests/unit/test_adapter_validation_block72.py` removed
- `tests/unit/test_analysis_runner_block25.py` removed
- `tests/unit/test_adapter_validation_more_block205.py` removed
- `tests/unit/test_analysis_runner_more_block45.py` removed
- `tests/unit/test_cli_analysis_runner_more2_block208.py` removed
- `tests/unit/test_batch_output_helpers_block32.py` removed
- `tests/unit/test_batch_output_more_block268.py` removed
- `tests/unit/test_batch_output_real_block54.py` removed
- `tests/unit/test_cli_commands_real_block55.py` removed
- `tests/unit/test_cli_error_paths_block56.py` removed
- `tests/unit/test_cli_interactive_block24.py` removed
- `tests/unit/test_cli_interactive_block345.py` removed
- `tests/unit/test_cli_interactive_full_block367.py` removed
- `tests/unit/test_cli_interactive_complete_coverage.py` removed
- `tests/unit/test_cli_interactive_full_block300.py` removed
- `tests/unit/test_cli_main_more_coverage_block320.py` removed
- `tests/unit/test_cli_main_dispatch_and_errors_block325.py` removed
- `tests/unit/test_cli_main_entrypoint_block266.py` removed
- `tests/unit/test_cli_display_base_block264.py` removed
- `tests/unit/test_cli_display_base_more_block207.py` removed
- `tests/unit/test_batch_discovery_coverage.py` removed
- `tests/unit/test_interactive_command_block262.py` removed
- `tests/unit/test_interactive_command_execute_block276.py`
- `tests/unit/test_cli_interactive_module_block265.py`

- next integration baseline candidates:
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
  `tests/integration/test_integration_global_wave_remaining_bridge.py` removed
  `tests/integration/test_integration_global_wave2_remaining_bridge.py` removed
  `tests/integration/test_integration_global_next5_to_100_bridge.py` removed
  `tests/integration/test_integration_top10_to_100_bridge.py` removed
  `tests/integration/test_integration_global_final16_bridge.py` removed
  `tests/integration/test_integration_global_top10_to_100_bridge.py` removed
  `tests/integration/test_integration_top10_wave10_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave9_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave8_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave7_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave6_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave5_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave6_remaining_edges.py` removed
  `tests/integration/test_integration_top10_wave5_remaining_edges.py` removed
  `tests/integration/test_integration_top10_wave4_unique_bridge.py` removed
  `tests/integration/test_integration_top10_wave3_unique_bridge.py` removed
  `tests/integration/test_integration_phase5_wave_b_closeout.py` removed
  `tests/integration/test_integration_phase5_to_100_bridge.py` removed
  `tests/integration/test_integration_phase5_to_95_bridge.py` removed
  `tests/integration/test_integration_phase4_to_95_bridge.py` removed
  `tests/integration/test_integration_cluster_under90_next_wave_gaps.py` removed
  `tests/integration/test_integration_cluster_under90_next_wave.py` removed
  `tests/integration/test_integration_phase3_to_90_bridge.py` removed
  `tests/integration/test_integration_phase3_gap_high_missing_bridge.py`

Already removed after overlapping behavior coverage was added:

- `tests/unit/historical/test_cli_batch_processing.py`
- `tests/unit/historical/test_pipeline_stages_common_branch_paths.py`
- `tests/unit/historical/test_pipeline_stages_metadata_branch_paths.py`
- `tests/unit/historical/test_pipeline_stages_security_branch_paths.py`
- `tests/unit/historical/test_pipeline_stages_detection_branch_paths.py`
- `tests/unit/historical/test_pipeline_stages_detection_coverage.py`
- `tests/unit/historical/test_pipeline_stages_hashing_branch_paths.py`
- `tests/unit/historical/test_pipeline_stages_format_missing_branches.py`
- `tests/unit/historical/test_analysis_pipeline_wave3.py`
- `tests/unit/historical/test_analysis_pipeline_full_block377.py`
- `tests/unit/historical/test_analysis_pipeline_more_full_block381.py`
- `tests/unit/historical/test_analysis_pipeline_progress_block138.py`
- `tests/unit/historical/test_pipeline_analysis_pipeline_and_stages_common_block335.py`
- `tests/unit/historical/test_batch_processing_additional_full_block375.py`
- `tests/unit/historical/test_batch_processing_branches_full_block369.py`
- `tests/unit/historical/test_batch_processing_helpers_block30.py`
- `tests/unit/historical/test_batch_processing_real_block53.py`
- `tests/unit/historical/test_cli_batch_processing_edges_real.py`
- `tests/unit/historical/test_cli_batch_processing_coverage.py`
- `tests/unit/historical/test_cli_main_extra_coverage.py`
- `tests/unit/historical/test_top10_next_cluster2_bridge.py`
- `tests/unit/historical/test_phase_current_block5_coverage.py`
- `tests/unit/historical/test_schemas_results_loader_coverage.py`
- `tests/unit/historical/test_schemas_converters_coverage.py`
- `tests/unit/historical/test_interactive_complete_100.py`
- `tests/unit/test_cli_validators_coverage.py`
- `tests/unit/test_schemas_converters.py`
- `tests/unit/test_display_complete_100.py`
- `tests/unit/test_analysis_runner_complete_100.py`
- `tests/unit/test_exploit_mitigation_coverage.py`
- `tests/unit/test_cli_coverage_targeted_real.py`
- `tests/unit/test_pipeline_misc_wave3.py`
- `tests/unit/test_hash_analyzers_wave3.py`
- `tests/unit/test_misc_analyzers_wave3.py`
- `tests/unit/test_adapters_wave3.py`
- `tests/unit/test_analyzers_core_wave3.py`
- `tests/unit/test_analyzer_modules_coverage.py`
- `tests/unit/test_analyzers_final_coverage.py`
- `tests/unit/test_analyzers_method_walk_block386.py`
- `tests/unit/test_cli_main_block232.py`
- `tests/unit/test_analysis_runner_status_block152.py`
- `tests/unit/test_abstractions_base_analyzer_block222.py`
- `tests/unit/test_analysis_runner_helpers_block129.py`
- `tests/unit/test_adapter_validation_address_size_block123.py`
- `tests/unit/test_analysis_runner_block50.py`
- `tests/unit/test_adapter_validation_block18.py`
- `tests/unit/test_adapter_validation_block72.py`
- `tests/unit/test_analysis_runner_block25.py`
- `tests/unit/test_adapter_validation_more_block205.py`
- `tests/unit/test_analysis_runner_more_block45.py`
- `tests/unit/test_cli_analysis_runner_more2_block208.py`
- `tests/unit/test_batch_output_helpers_block32.py`
- `tests/unit/test_batch_output_more_block268.py`
- `tests/unit/test_batch_output_real_block54.py`
- `tests/unit/test_cli_commands_real_block55.py`
- `tests/unit/test_cli_error_paths_block56.py`

Remaining files should now be treated as deliberate transition coverage, not as default places to add new behavior tests.
