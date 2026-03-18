# Testing Migration Status

## Unit

Completed blocks:

- CLI main
- batch processing
- analysis pipeline
- pipeline stages common/detection/format/hashing/metadata/security
- converters/default registry/results loader
- misc analyzers
- adapters validation/query helpers
- core analyzer behavior
- analyzer module behavior
- final analyzer behavior edge cases
- representative analyzer registry behavior
- cli main historical block removal
- analysis runner status block removal
- base analyzer historical block removal
- analysis runner helpers block removal
- adapter validation address-size block removal
- analysis runner block removal
- adapter validation block removal
- adapter validation block72 removal
- analysis runner block25 removal
- adapter validation more-block removal
- analysis runner more-block removal
- cli analysis runner more2 block removal
- batch output helpers block removal
- batch output more block removal
- batch output real block removal
- cli commands real block removal
- cli error paths block removal
- cli interactive block24 removal
- cli interactive block345 removal
- cli interactive full block367 removal
- cli interactive complete coverage removal
- cli interactive full block300 removal
- cli main more coverage block320 removal
- cli main dispatch/errors block325 removal
- cli main entrypoint block266 removal
- cli display base block264 removal
- cli display base more block207 removal
- batch discovery coverage removal
- interactive command block262 removal

Current baseline:

- `tests/unit` historical naming baseline: `349`
- `tests/integration` historical naming baseline: `33`

Recently removed historical unit files:

- `test_analysis_pipeline_wave3.py`
- `test_analysis_pipeline_full_block377.py`
- `test_analysis_pipeline_more_full_block381.py`
- `test_analysis_pipeline_progress_block138.py`
- `test_pipeline_analysis_pipeline_and_stages_common_block335.py`
- `test_batch_processing_additional_full_block375.py`
- `test_batch_processing_branches_full_block369.py`
- `test_batch_processing_helpers_block30.py`
- `test_batch_processing_real_block53.py`
- `test_cli_batch_processing_coverage.py`
- `test_cli_main_extra_coverage.py`
- `test_top10_next_cluster2_bridge.py`
- `test_phase_current_block5_coverage.py`
- `test_schemas_results_loader_coverage.py`
- `test_schemas_converters_coverage.py`
- `test_interactive_complete_100.py`
- `test_cli_validators_coverage.py`
- `test_schemas_converters.py`
- `test_display_complete_100.py`
- `test_analysis_runner_complete_100.py`
- `test_exploit_mitigation_coverage.py`
- `test_cli_coverage_targeted_real.py`
- `test_pipeline_misc_wave3.py`
- `test_hash_analyzers_wave3.py`
- `test_misc_analyzers_wave3.py`
- `test_adapters_wave3.py`
- `test_analyzers_core_wave3.py`
- `test_analyzer_modules_coverage.py`
- `test_analyzers_final_coverage.py`
- `test_analyzers_method_walk_block386.py`
- `test_cli_main_block232.py`
- `test_analysis_runner_status_block152.py`
- `test_abstractions_base_analyzer_block222.py`
- `test_analysis_runner_helpers_block129.py`
- `test_adapter_validation_address_size_block123.py`
- `test_analysis_runner_block50.py`
- `test_adapter_validation_block18.py`
- `test_adapter_validation_block72.py`
- `test_analysis_runner_block25.py`
- `test_adapter_validation_more_block205.py`
- `test_analysis_runner_more_block45.py`
- `test_cli_analysis_runner_more2_block208.py`
- `test_batch_output_helpers_block32.py`
- `test_batch_output_more_block268.py`
- `test_batch_output_real_block54.py`
- `test_cli_commands_real_block55.py`
- `test_cli_error_paths_block56.py`
- `test_cli_interactive_block24.py`
- `test_cli_interactive_block345.py`
- `test_cli_interactive_full_block367.py`
- `test_cli_interactive_complete_coverage.py`
- `test_cli_interactive_full_block300.py`
- `test_cli_main_more_coverage_block320.py`
- `test_cli_main_dispatch_and_errors_block325.py`
- `test_cli_main_entrypoint_block266.py`
- `test_cli_display_base_block264.py`
- `test_cli_display_base_more_block207.py`
- `test_batch_discovery_coverage.py`
- `test_interactive_command_block262.py`

Current pattern:

- behavior-oriented tests live in `tests/unit/product/`
- archaeology/coverage holdovers live in `tests/unit/historical/`
- structural enforcement lives in `tests/unit/guardrails/`

## Integration

Started:

- `tests/integration/product/` contains initial behavior suites
- pipeline-oriented integration coverage has been split into `product/` and `historical/`
- hashing/similarity integration coverage has been split into `product/` and `historical/`
- the `remaining_edges` top10 integration holdovers have been removed
- the targeted integration coverage bridge has been removed
- the targeted small-gaps integration bridge has been removed
- the CLI/validators/batch-output gaps bridge has been removed
- the circuit breaker bridge has been removed
- the CLI/retry targeted bridge has been removed
- the CLI/retry phase bridge has been removed
- the analyze-command integration bridge has been removed
- the batch-command integration bridge has been removed
- the common CLI-commands integration bridge has been removed
- the config-command integration bridge has been removed
- the interactive-command integration bridge has been removed
- the display-metadata integration bridge has been removed
- the display-similarity integration bridge has been removed
- the global wave-remaining integration bridge has been removed
- the global wave2-remaining integration bridge has been removed
- the global next5-to-100 integration bridge has been removed
- the top10-to-100 integration bridge has been removed
- the global final16 bridge has been removed
- the global top10-to-100 bridge has been removed
- the top10 wave10 unique bridge has been removed
- the top10 wave9 unique bridge has been removed
- the top10 wave8 unique bridge has been removed
- the top10 wave7 unique bridge has been removed
- the top10 wave6 unique bridge has been removed
- the top10 wave5 unique bridge has been removed
- the top10 wave6 remaining-edges bridge has been removed
- the top10 wave5 remaining-edges bridge has been removed
- the top10 wave4 unique bridge has been removed
- the top10 wave4 remaining-edges bridge has been removed
- the top10 wave3 unique bridge has been removed
- the phase5 wave-b closeout bridge has been removed
- the phase5 to-100 bridge has been removed
- the phase5 to-95 bridge has been removed
- the phase4 to-95 bridge has been removed
- the cluster-under90 next-wave gaps bridge has been removed
- the cluster-under90 next-wave bridge has been removed
- the phase3 to-90 bridge has been removed

## Next cleanup goal

Delete additional historical files whose behavior is already protected by product tests, prioritizing names that still reduce the historical baselines when removed. Immediate next targets are `test_interactive_command_execute_block276.py` in unit and `test_integration_phase3_gap_high_missing_bridge.py` in integration.
