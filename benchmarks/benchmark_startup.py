#!/usr/bin/env python3
"""
Startup Performance Benchmark for r2inspect

This script measures baseline startup performance and memory usage before
implementing lazy loading optimizations.

Copyright (C) 2025 Marc Rivero López
Licensed under GPLv3
https://www.gnu.org/licenses/gpl-3.0.html
"""

import cProfile
import gc
import pstats
import sys
import time
import tracemalloc
from io import StringIO
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def benchmark_import_time(iterations=10):
    """Benchmark time to import main module"""
    times = []

    for _ in range(iterations):
        # Force module unload for clean measurement
        if "r2inspect" in sys.modules:
            # Clear all r2inspect modules
            to_remove = [k for k in sys.modules if k.startswith("r2inspect")]
            for module in to_remove:
                del sys.modules[module]

        gc.collect()

        start = time.perf_counter()
        import r2inspect

        end = time.perf_counter()

        elapsed = (end - start) * 1000  # Convert to milliseconds
        times.append(elapsed)

    return {
        "mean": sum(times) / len(times),
        "min": min(times),
        "max": max(times),
        "median": sorted(times)[len(times) // 2],
        "samples": times,
    }


def benchmark_r2inspector_import(iterations=10):
    """Benchmark time to import R2Inspector class"""
    times = []

    for _ in range(iterations):
        # Force module unload
        if "r2inspect" in sys.modules:
            to_remove = [k for k in sys.modules if k.startswith("r2inspect")]
            for module in to_remove:
                del sys.modules[module]

        gc.collect()

        start = time.perf_counter()
        from r2inspect import R2Inspector

        end = time.perf_counter()

        elapsed = (end - start) * 1000
        times.append(elapsed)

    return {
        "mean": sum(times) / len(times),
        "min": min(times),
        "max": max(times),
        "median": sorted(times)[len(times) // 2],
        "samples": times,
    }


def benchmark_registry_creation(iterations=10):
    """Benchmark time to create default registry"""
    times = []

    for _ in range(iterations):
        # Force module unload
        if "r2inspect" in sys.modules:
            to_remove = [k for k in sys.modules if k.startswith("r2inspect")]
            for module in to_remove:
                del sys.modules[module]

        gc.collect()

        from r2inspect.registry.default_registry import create_default_registry

        start = time.perf_counter()
        registry = create_default_registry()
        end = time.perf_counter()

        elapsed = (end - start) * 1000
        times.append(elapsed)

    return {
        "mean": sum(times) / len(times),
        "min": min(times),
        "max": max(times),
        "median": sorted(times)[len(times) // 2],
        "samples": times,
        "analyzer_count": len(registry),
    }


def benchmark_memory_usage():
    """Benchmark memory usage of importing r2inspect"""
    # Clear modules
    if "r2inspect" in sys.modules:
        to_remove = [k for k in sys.modules if k.startswith("r2inspect")]
        for module in to_remove:
            del sys.modules[module]

    gc.collect()

    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    from r2inspect import R2Inspector
    from r2inspect.registry.default_registry import create_default_registry

    create_default_registry()

    snapshot_after = tracemalloc.take_snapshot()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate top memory allocations
    top_stats = snapshot_after.compare_to(snapshot_before, "lineno")

    return {
        "current_mb": current / 1024 / 1024,
        "peak_mb": peak / 1024 / 1024,
        "top_allocations": [
            {
                "file": stat.traceback.format()[0] if stat.traceback else "unknown",
                "size_mb": stat.size / 1024 / 1024,
                "count": stat.count,
            }
            for stat in top_stats[:10]
        ],
    }


def profile_import():
    """Profile the import process to identify hotspots"""
    # Clear modules
    if "r2inspect" in sys.modules:
        to_remove = [k for k in sys.modules if k.startswith("r2inspect")]
        for module in to_remove:
            del sys.modules[module]

    gc.collect()

    profiler = cProfile.Profile()
    profiler.enable()

    from r2inspect import R2Inspector
    from r2inspect.registry.default_registry import create_default_registry

    create_default_registry()

    profiler.disable()

    # Capture stats
    stream = StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.sort_stats("cumulative")
    stats.print_stats(30)

    return stream.getvalue()


def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_benchmark_results(name, results):
    """Print formatted benchmark results"""
    print(f"\n{name}:")
    print(f"  Mean:   {results['mean']:.2f} ms")
    print(f"  Median: {results['median']:.2f} ms")
    print(f"  Min:    {results['min']:.2f} ms")
    print(f"  Max:    {results['max']:.2f} ms")

    if "analyzer_count" in results:
        print(f"  Analyzers: {results['analyzer_count']}")


def main():
    """Run all benchmarks and report results"""
    print_section("r2inspect Baseline Performance Benchmark")
    print("\nThis benchmark establishes baseline metrics before lazy loading optimization.")
    print("Target: Reduce startup time from ~500ms to ~50ms (90% reduction)")

    # Benchmark 1: Basic module import
    print_section("1. Module Import Time")
    print("Measuring: import r2inspect")
    import_results = benchmark_import_time()
    print_benchmark_results("Results", import_results)

    # Benchmark 2: R2Inspector class import
    print_section("2. R2Inspector Import Time")
    print("Measuring: from r2inspect import R2Inspector")
    class_results = benchmark_r2inspector_import()
    print_benchmark_results("Results", class_results)

    # Benchmark 3: Registry creation
    print_section("3. Registry Creation Time")
    print("Measuring: create_default_registry()")
    registry_results = benchmark_registry_creation()
    print_benchmark_results("Results", registry_results)

    # Benchmark 4: Memory usage
    print_section("4. Memory Usage")
    print("Measuring: Memory consumption during import")
    memory_results = benchmark_memory_usage()
    print("\nMemory Usage:")
    print(f"  Current: {memory_results['current_mb']:.2f} MB")
    print(f"  Peak:    {memory_results['peak_mb']:.2f} MB")

    print("\nTop Memory Allocations:")
    for i, alloc in enumerate(memory_results["top_allocations"][:5], 1):
        print(f"  {i}. {alloc['size_mb']:.3f} MB - {alloc['file']}")

    # Benchmark 5: Profiling
    print_section("5. Import Profile (Top 30 Functions)")
    profile_output = profile_import()
    print("\n" + profile_output)

    # Summary
    print_section("Baseline Summary")
    total_startup = import_results["mean"] + class_results["mean"] + registry_results["mean"]

    print(f"\nTotal Startup Time: {total_startup:.2f} ms")
    print(f"Memory Overhead:    {memory_results['peak_mb']:.2f} MB")
    print(f"Analyzers Loaded:   {registry_results.get('analyzer_count', 0)}")

    print("\nOptimization Targets:")
    print(f"  - Reduce startup time to: {total_startup * 0.1:.2f} ms (90% reduction)")
    print("  - Reduce memory usage by: ~50%")
    print("  - Maintain 100% backward compatibility")

    print("\n" + "=" * 80)
    print("Benchmark complete. Save these results for comparison after optimization.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
