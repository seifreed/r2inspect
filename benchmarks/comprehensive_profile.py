#!/usr/bin/env python3
"""
Comprehensive Performance Profiling for r2inspect
Uses cProfile to identify bottlenecks

Copyright (C) 2025 Marc Rivero López
Licensed under GPLv3
"""

import cProfile
import io
import pstats
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def profile_import():
    """Profile the import process"""
    pr = cProfile.Profile()
    pr.enable()

    from r2inspect import R2Inspector
    from r2inspect.registry.default_registry import create_default_registry

    registry = create_default_registry()

    pr.disable()

    # Print statistics
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(30)

    print("=" * 80)
    print("IMPORT PROFILING RESULTS (Top 30 by cumulative time)")
    print("=" * 80)
    print(s.getvalue())

    # Also sort by time
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("time")
    ps.print_stats(20)

    print("\n" + "=" * 80)
    print("IMPORT PROFILING RESULTS (Top 20 by total time)")
    print("=" * 80)
    print(s.getvalue())

    return registry


def profile_registry_operations(registry):
    """Profile registry access patterns"""
    pr = cProfile.Profile()
    pr.enable()

    # Access various analyzers
    for _ in range(10):
        registry.get_analyzer_class("pe_analyzer")
        registry.get_analyzer_class("ssdeep")
        registry.get_analyzer_class("yara_analyzer")

    # List analyzers
    registry.list_analyzers()

    # Get by category
    from r2inspect.registry.analyzer_registry import AnalyzerCategory

    registry.get_by_category(AnalyzerCategory.HASHING)
    registry.get_by_category(AnalyzerCategory.FORMAT)

    pr.disable()

    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats("cumulative")
    ps.print_stats(20)

    print("\n" + "=" * 80)
    print("REGISTRY OPERATIONS PROFILING (Top 20 by cumulative time)")
    print("=" * 80)
    print(s.getvalue())


def analyze_module_import_overhead():
    """Analyze which modules take longest to import"""
    import importlib
    import sys

    modules_to_test = [
        ("r2inspect.modules.pe_analyzer", "PEAnalyzer"),
        ("r2inspect.modules.ssdeep_analyzer", "SSDeepAnalyzer"),
        ("r2inspect.modules.yara_analyzer", "YaraAnalyzer"),
        ("r2inspect.modules.packer_detector", "PackerDetector"),
        ("r2inspect.modules.crypto_analyzer", "CryptoAnalyzer"),
    ]

    print("\n" + "=" * 80)
    print("INDIVIDUAL MODULE IMPORT TIMES")
    print("=" * 80)

    for module_path, class_name in modules_to_test:
        # Remove module if already imported
        if module_path in sys.modules:
            del sys.modules[module_path]

        start = time.perf_counter()
        importlib.import_module(module_path)
        elapsed = time.perf_counter() - start

        print(f"{module_path:50s}: {elapsed * 1000:8.2f} ms")


def check_pipeline_performance():
    """Profile pipeline execution without actual binary"""
    import time

    from r2inspect.pipeline import AnalysisPipeline, AnalysisStage

    print("\n" + "=" * 80)
    print("PIPELINE PERFORMANCE TEST")
    print("=" * 80)

    # Create mock stages
    def mock_analyzer():
        time.sleep(0.01)  # Simulate 10ms of work
        return {"result": "success"}

    pipeline = AnalysisPipeline()

    for i in range(10):
        pipeline.add_stage(AnalysisStage(name=f"stage_{i}", analyzer=mock_analyzer))

    # Sequential execution
    start = time.perf_counter()
    pipeline.execute(parallel=False)
    seq_time = time.perf_counter() - start

    # Parallel execution
    start = time.perf_counter()
    pipeline.execute(parallel=True)
    par_time = time.perf_counter() - start

    print(f"Sequential execution:  {seq_time * 1000:.2f} ms")
    print(f"Parallel execution:    {par_time * 1000:.2f} ms")
    print(f"Speedup:               {seq_time / par_time:.2f}x")
    print("Expected time (seq):   ~100 ms (10 stages × 10ms)")
    print("Expected time (par):   ~10-20 ms (parallel + overhead)")


def check_modules_init_imports():
    """Check what gets imported by r2inspect.modules.__init__"""
    import sys

    before = set(sys.modules.keys())

    from r2inspect import modules

    after = set(sys.modules.keys())

    new_modules = after - before
    r2inspect_new = [m for m in new_modules if "r2inspect" in m]

    print("\n" + "=" * 80)
    print("MODULES IMPORTED BY r2inspect.modules.__init__")
    print("=" * 80)
    print(f"Total new modules: {len(new_modules)}")
    print(f"r2inspect modules: {len(r2inspect_new)}")
    print("\nr2inspect modules loaded:")
    for mod in sorted(r2inspect_new):
        print(f"  {mod}")


def main():
    print("COMPREHENSIVE PERFORMANCE PROFILING")
    print("=" * 80)
    print()

    # Profile import
    registry = profile_import()

    # Profile registry operations
    profile_registry_operations(registry)

    # Analyze individual module imports
    analyze_module_import_overhead()

    # Check pipeline performance
    check_pipeline_performance()

    # Check modules.__init__
    check_modules_init_imports()


if __name__ == "__main__":
    main()
