#!/usr/bin/env python3
"""
End-to-end analysis performance test

Copyright (C) 2025 Marc Rivero López
Licensed under GPLv3
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def measure_end_to_end():
    """Measure complete analysis flow"""
    test_file = "/bin/ls"

    print("=" * 80)
    print("END-TO-END ANALYSIS PERFORMANCE")
    print("=" * 80)
    print(f"Test file: {test_file}")
    print(f"File size: {Path(test_file).stat().st_size / 1024:.1f} KB")
    print()

    # Import phase
    print("Phase 1: Import")
    print("-" * 80)
    import_start = time.perf_counter()
    from r2inspect import create_inspector

    import_time = time.perf_counter() - import_start
    print(f"Import time: {import_time * 1000:.2f} ms")
    print()

    # Initialization phase
    print("Phase 2: R2Inspector Initialization")
    print("-" * 80)
    init_start = time.perf_counter()
    inspector = create_inspector(test_file, verbose=False)
    init_time = time.perf_counter() - init_start
    print(f"Initialization time: {init_time * 1000:.2f} ms")
    print()

    # Analysis phase
    print("Phase 3: Analysis")
    print("-" * 80)
    analysis_start = time.perf_counter()
    results = inspector.analyze()
    analysis_time = time.perf_counter() - analysis_start
    print(f"Analysis time: {analysis_time * 1000:.2f} ms")
    print()

    # Cleanup
    inspector.close()

    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    total_time = import_time + init_time + analysis_time
    print(
        f"Import:         {import_time * 1000:8.2f} ms ({import_time / total_time * 100:5.1f}%)"
    )
    print(
        f"Initialization: {init_time * 1000:8.2f} ms ({init_time / total_time * 100:5.1f}%)"
    )
    print(
        f"Analysis:       {analysis_time * 1000:8.2f} ms ({analysis_time / total_time * 100:5.1f}%)"
    )
    print(f"Total:          {total_time * 1000:8.2f} ms")
    print()

    # Memory usage
    if "memory_stats" in results:
        mem = results["memory_stats"]
        print("Memory Usage:")
        print(f"  Initial:      {mem.get('initial_memory_mb', 0):.2f} MB")
        print(f"  Final:        {mem.get('final_memory_mb', 0):.2f} MB")
        print(f"  Used:         {mem.get('memory_used_mb', 0):.2f} MB")
        print()

    return {
        "import_time_ms": import_time * 1000,
        "init_time_ms": init_time * 1000,
        "analysis_time_ms": analysis_time * 1000,
        "total_time_ms": total_time * 1000,
    }


if __name__ == "__main__":
    try:
        stats = measure_end_to_end()
    except Exception as e:
        print(f"\nError during analysis: {e}")
        import traceback

        traceback.print_exc()
