#!/usr/bin/env python3
"""
Performance Analysis Script for r2inspect
Measures startup time, import time, memory usage, and lazy loading effectiveness

Copyright (C) 2025 Marc Rivero López
Licensed under GPLv3
"""

import gc
import os
import sys
import time
import tracemalloc
from pathlib import Path
from statistics import mean, median, stdev
from typing import Any

# Add r2inspect to path
sys.path.insert(0, str(Path(__file__).parent))


def measure_import_time(iterations=10):
    """Measure time to import r2inspect"""
    times = []

    for _ in range(iterations):
        # Remove all r2inspect modules to force fresh import
        modules_to_remove = [k for k in sys.modules if "r2inspect" in k]
        for module in modules_to_remove:
            del sys.modules[module]

        gc.collect()

        start = time.perf_counter()
        import r2inspect

        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)  # Convert to ms

    return {
        "mean": mean(times),
        "median": median(times),
        "std_dev": stdev(times) if len(times) > 1 else 0,
        "min": min(times),
        "max": max(times),
        "samples": times,
    }


def measure_registry_creation_time():
    """Measure time to create default registry"""
    from r2inspect.registry.default_registry import create_default_registry

    start = time.perf_counter()
    registry = create_default_registry()
    elapsed = time.perf_counter() - start

    return {
        "time_ms": elapsed * 1000,
        "analyzer_count": len(registry),
        "time_per_analyzer_ms": (elapsed * 1000) / len(registry) if len(registry) > 0 else 0,
    }


def check_lazy_loading_status():
    """Check if lazy loading is working"""
    from r2inspect.registry.default_registry import create_default_registry

    registry = create_default_registry()

    # Check if lazy loader is active
    has_lazy_loader = hasattr(registry, "_lazy_loader") and registry._lazy_loader is not None

    if not has_lazy_loader:
        return {"enabled": False, "reason": "No lazy loader found"}

    stats = registry._lazy_loader.get_stats()

    # Check what modules are actually loaded
    loaded_modules = [m for m in sys.modules if "r2inspect.modules" in m]

    return {
        "enabled": True,
        "stats": stats,
        "loaded_module_count": len(loaded_modules),
        "loaded_modules": sorted(loaded_modules),
    }


def measure_memory_usage():
    """Measure memory usage during import"""
    tracemalloc.start()

    # Baseline
    tracemalloc.take_snapshot()
    baseline_current, _baseline_peak = tracemalloc.get_traced_memory()

    # Import r2inspect
    from r2inspect import R2Inspector

    tracemalloc.take_snapshot()
    import_current, _import_peak = tracemalloc.get_traced_memory()

    # Create registry
    from r2inspect.registry.default_registry import create_default_registry

    create_default_registry()

    registry_current, registry_peak = tracemalloc.get_traced_memory()

    tracemalloc.stop()

    return {
        "baseline_mb": baseline_current / (1024 * 1024),
        "after_import_mb": import_current / (1024 * 1024),
        "after_registry_mb": registry_current / (1024 * 1024),
        "import_overhead_mb": (import_current - baseline_current) / (1024 * 1024),
        "registry_overhead_mb": (registry_current - import_current) / (1024 * 1024),
        "peak_mb": registry_peak / (1024 * 1024),
    }


def measure_first_analyzer_access():
    """Measure time to first analyzer access"""
    from r2inspect.registry.default_registry import create_default_registry

    registry = create_default_registry()

    # Measure access time for different analyzers
    analyzers_to_test = ["pe_analyzer", "ssdeep", "yara_analyzer", "packer_detector"]
    results = {}

    for analyzer_name in analyzers_to_test:
        start = time.perf_counter()
        analyzer_class = registry.get_analyzer_class(analyzer_name)
        elapsed = time.perf_counter() - start

        if analyzer_class:
            results[analyzer_name] = {
                "time_ms": elapsed * 1000,
                "loaded": analyzer_class is not None,
            }
        else:
            results[analyzer_name] = {
                "time_ms": 0,
                "loaded": False,
                "error": "Not found",
            }

    return results


def measure_module_loading_pattern():
    """Check which modules are loaded at different stages"""
    stages = []

    # Stage 1: Before import
    before_import = len([m for m in sys.modules if "r2inspect" in m])
    stages.append(
        {
            "stage": "before_import",
            "r2inspect_modules": before_import,
            "total_modules": len(sys.modules),
        }
    )

    # Stage 2: After basic import
    from r2inspect import R2Inspector

    after_import = len([m for m in sys.modules if "r2inspect" in m])
    stages.append(
        {
            "stage": "after_import",
            "r2inspect_modules": after_import,
            "total_modules": len(sys.modules),
        }
    )

    # Stage 3: After registry creation
    from r2inspect.registry.default_registry import create_default_registry

    create_default_registry()
    after_registry = len([m for m in sys.modules if "r2inspect" in m])
    stages.append(
        {
            "stage": "after_registry",
            "r2inspect_modules": after_registry,
            "total_modules": len(sys.modules),
        }
    )

    # Stage 4: Check analyzer modules specifically
    analyzer_modules = [
        m for m in sys.modules if "r2inspect.modules" in m and not m.endswith("__init__")
    ]
    stages.append(
        {
            "stage": "analyzer_modules_loaded",
            "count": len(analyzer_modules),
            "modules": sorted(analyzer_modules),
        }
    )

    return stages


def main():
    _print_header()
    import_stats = _phase_import_time()
    registry_stats = _phase_registry_time()
    lazy_status = _phase_lazy_loading()
    memory_stats = _phase_memory_usage()
    _phase_first_analyzer_access()
    _phase_module_loading_pattern()
    _print_summary(import_stats, registry_stats, memory_stats, lazy_status)


def _print_header() -> None:
    print("=" * 80)
    print("R2INSPECT PERFORMANCE ANALYSIS")
    print("=" * 80)
    print()


def _phase_import_time() -> dict[str, Any]:
    print("Phase 1: Import Time Measurement")
    print("-" * 80)
    import_stats = measure_import_time(iterations=5)
    print(f"Mean import time:   {import_stats['mean']:.2f} ms")
    print(f"Median import time: {import_stats['median']:.2f} ms")
    print(f"Std deviation:      {import_stats['std_dev']:.2f} ms")
    print(f"Min time:           {import_stats['min']:.2f} ms")
    print(f"Max time:           {import_stats['max']:.2f} ms")
    print(f"All samples:        {[f'{t:.2f}' for t in import_stats['samples']]}")
    print()
    return import_stats


def _phase_registry_time() -> dict[str, Any]:
    print("Phase 2: Registry Creation Time")
    print("-" * 80)
    registry_stats = measure_registry_creation_time()
    print(f"Registry creation:  {registry_stats['time_ms']:.2f} ms")
    print(f"Analyzers count:    {registry_stats['analyzer_count']}")
    print(f"Time per analyzer:  {registry_stats['time_per_analyzer_ms']:.4f} ms")
    print()
    return registry_stats


def _phase_lazy_loading() -> dict[str, Any]:
    print("Phase 3: Lazy Loading Verification")
    print("-" * 80)
    lazy_status = check_lazy_loading_status()
    print(f"Lazy loading enabled: {lazy_status['enabled']}")
    if lazy_status["enabled"]:
        stats = lazy_status["stats"]
        print(f"Registered analyzers: {stats['registered']}")
        print(f"Loaded analyzers:     {stats['loaded']}")
        print(f"Unloaded analyzers:   {stats['unloaded']}")
        print(f"Lazy ratio:           {stats['lazy_ratio']:.1%}")
        print(f"Cache hits:           {stats['cache_hits']}")
        print(f"Cache misses:         {stats['cache_misses']}")
        print(f"Cache hit rate:       {stats['cache_hit_rate']:.1%}")
        print(f"Loaded module count:  {lazy_status['loaded_module_count']}")
        if stats["loaded"] > 0:
            print("\nActually loaded modules:")
            for mod in lazy_status["loaded_modules"]:
                print(f"  - {mod}")
    else:
        print(f"Reason: {lazy_status.get('reason', 'Unknown')}")
    print()
    return lazy_status


def _phase_memory_usage() -> dict[str, Any]:
    print("Phase 4: Memory Usage")
    print("-" * 80)
    memory_stats = measure_memory_usage()
    print(f"Baseline memory:        {memory_stats['baseline_mb']:.2f} MB")
    print(f"After import:           {memory_stats['after_import_mb']:.2f} MB")
    print(f"After registry:         {memory_stats['after_registry_mb']:.2f} MB")
    print(f"Import overhead:        {memory_stats['import_overhead_mb']:.2f} MB")
    print(f"Registry overhead:      {memory_stats['registry_overhead_mb']:.2f} MB")
    print(f"Peak memory:            {memory_stats['peak_mb']:.2f} MB")
    print()
    return memory_stats


def _phase_first_analyzer_access() -> None:
    print("Phase 5: First Analyzer Access Time")
    print("-" * 80)
    access_times = measure_first_analyzer_access()
    for analyzer, data in access_times.items():
        if data["loaded"]:
            print(f"{analyzer:20s}: {data['time_ms']:8.2f} ms")
        else:
            print(f"{analyzer:20s}: Not found ({data.get('error', 'Unknown')})")
    print()


def _phase_module_loading_pattern() -> None:
    print("Phase 6: Module Loading Pattern")
    print("-" * 80)
    loading_pattern = measure_module_loading_pattern()
    for stage in loading_pattern:
        if "modules" in stage:
            print(f"{stage['stage']:30s}: {stage['count']} modules")
            if 0 < stage["count"] < 10:
                for mod in stage["modules"]:
                    print(f"  - {mod}")
        else:
            print(
                f"{stage['stage']:30s}: {stage['r2inspect_modules']} r2inspect modules "
                f"({stage['total_modules']} total)"
            )
    print()


def _print_summary(
    import_stats: dict[str, Any],
    registry_stats: dict[str, Any],
    memory_stats: dict[str, Any],
    lazy_status: dict[str, Any],
) -> None:
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Import time:          {import_stats['mean']:.2f} ms")
    print(f"Registry creation:    {registry_stats['time_ms']:.2f} ms")
    print(f"Total startup:        {import_stats['mean'] + registry_stats['time_ms']:.2f} ms")
    print(
        "Memory overhead:      "
        f"{memory_stats['import_overhead_mb'] + memory_stats['registry_overhead_mb']:.2f} MB"
    )
    if lazy_status["enabled"]:
        stats = lazy_status["stats"]
        print("\nLazy Loading Effectiveness:")
        print(f"  Lazy ratio:         {stats['lazy_ratio']:.1%}")
        print(f"  Modules saved:      {stats['unloaded']}/{stats['registered']}")
        if stats["load_times"]:
            avg_load_time = mean(stats["load_times"].values())
            saved_time = avg_load_time * stats["unloaded"]
            print(f"  Estimated savings:  ~{saved_time:.0f} ms")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
