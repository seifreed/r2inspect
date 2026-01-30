#!/usr/bin/env python3
# Copyright (c) 2025 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
"""
Parallel Pipeline Performance Benchmark

Benchmarks parallel execution performance compared to sequential execution
across various scenarios:
- I/O-bound stages (file access, network, etc.)
- CPU-bound stages (computation)
- Mixed workloads
- Varying worker counts
- Realistic malware analysis pipelines

Usage:
    python benchmarks/parallel_pipeline_benchmark.py

Output:
    Detailed performance report with speedup analysis and recommendations
"""

import os
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from r2inspect.pipeline.analysis_pipeline import AnalysisPipeline, AnalysisStage


@dataclass
class BenchmarkResult:
    """Results from a single benchmark run."""

    name: str
    sequential_time: float
    parallel_times: dict[int, float]  # workers -> time
    speedups: dict[int, float]  # workers -> speedup
    efficiency: dict[int, float]  # workers -> efficiency (speedup / workers)


def benchmark_pipeline(
    name: str,
    stage_factory: Callable[[int], list[AnalysisStage]],
    num_stages: int,
    worker_counts: list[int],
    num_runs: int = 3,
) -> BenchmarkResult:
    """
    Benchmark a pipeline configuration.

    Args:
        name: Benchmark name
        stage_factory: Function that creates list of stages given number
        num_stages: Number of stages to create
        worker_counts: List of worker counts to test
        num_runs: Number of runs to average

    Returns:
        BenchmarkResult with timing data
    """
    print(f"\nBenchmarking: {name}")
    print(f"  Stages: {num_stages}")
    print(f"  Runs per configuration: {num_runs}")

    # Sequential benchmark
    print("  Running sequential...")
    sequential_times = []
    for _ in range(num_runs):
        pipeline = AnalysisPipeline()
        for stage in stage_factory(num_stages):
            pipeline.add_stage(stage)

        start = time.time()
        pipeline.execute(parallel=False)
        elapsed = time.time() - start
        sequential_times.append(elapsed)

    seq_time = statistics.mean(sequential_times)
    print(f"    Sequential: {seq_time:.3f}s (avg of {num_runs} runs)")

    # Parallel benchmarks
    parallel_times = {}
    for workers in worker_counts:
        print(f"  Running parallel ({workers} workers)...")
        times = []
        for _ in range(num_runs):
            pipeline = AnalysisPipeline(max_workers=workers)
            for stage in stage_factory(num_stages):
                pipeline.add_stage(stage)

            start = time.time()
            pipeline.execute(parallel=True)
            elapsed = time.time() - start
            times.append(elapsed)

        parallel_times[workers] = statistics.mean(times)
        print(f"    {workers} workers: {parallel_times[workers]:.3f}s")

    # Calculate speedups and efficiency
    speedups = {w: seq_time / parallel_times[w] for w in worker_counts}
    efficiency = {w: speedups[w] / w for w in worker_counts}

    return BenchmarkResult(
        name=name,
        sequential_time=seq_time,
        parallel_times=parallel_times,
        speedups=speedups,
        efficiency=efficiency,
    )


def create_io_bound_stages(num_stages: int) -> list[AnalysisStage]:
    """Create I/O-bound stages (simulates file access, network, etc.)."""
    stages = []
    for i in range(num_stages):

        def analyzer(idx=i) -> dict[str, Any]:
            time.sleep(0.05)  # Simulate I/O operation
            return {"stage": idx, "type": "io_bound"}

        stages.append(AnalysisStage(f"io_stage_{i}", analyzer))
    return stages


def create_cpu_bound_stages(num_stages: int) -> list[AnalysisStage]:
    """Create CPU-bound stages (simulates computation)."""
    stages = []
    for i in range(num_stages):

        def analyzer(idx=i) -> dict[str, Any]:
            # Simulate CPU-intensive work
            result = 0
            for _ in range(100000):
                result += 1
            return {"stage": idx, "type": "cpu_bound", "result": result}

        stages.append(AnalysisStage(f"cpu_stage_{i}", analyzer))
    return stages


def create_mixed_stages(num_stages: int) -> list[AnalysisStage]:
    """Create mixed I/O and CPU-bound stages."""
    stages = []
    for i in range(num_stages):
        if i % 2 == 0:
            # I/O-bound
            def analyzer_io(idx=i) -> dict[str, Any]:
                time.sleep(0.03)
                return {"stage": idx, "type": "io"}

            stages.append(AnalysisStage(f"mixed_stage_{i}", analyzer_io))
        else:
            # CPU-bound
            def analyzer_cpu(idx=i) -> dict[str, Any]:
                result = sum(range(50000))
                return {"stage": idx, "type": "cpu", "result": result}

            stages.append(AnalysisStage(f"mixed_stage_{i}", analyzer_cpu))
    return stages


def create_dependency_chain_stages(num_stages: int) -> list[AnalysisStage]:
    """Create stages with dependency chain (limited parallelism)."""
    stages = []
    for i in range(num_stages):
        deps = [f"chain_stage_{i - 1}"] if i > 0 else []

        def analyzer(idx=i) -> dict[str, Any]:
            time.sleep(0.02)
            return {"stage": idx, "type": "chained"}

        stages.append(AnalysisStage(f"chain_stage_{i}", analyzer, dependencies=deps))
    return stages


def create_realistic_malware_pipeline_stages(num_stages: int) -> list[AnalysisStage]:
    """
    Create realistic malware analysis pipeline.

    Simulates:
    - file_info (quick, no dependencies)
    - format_detection (quick, depends on file_info)
    - parallel group: format_analysis, metadata, hashing (I/O-bound)
    - detection (depends on metadata)
    """
    stages = []

    # Stage 1: file_info (quick)
    def file_info_analyzer() -> dict[str, Any]:
        time.sleep(0.01)
        return {"type": "file_info"}

    stages.append(AnalysisStage("file_info", file_info_analyzer))

    # Stage 2: format_detection (quick, depends on file_info)
    def format_analyzer() -> dict[str, Any]:
        time.sleep(0.01)
        return {"type": "format_detection"}

    stages.append(AnalysisStage("format_detection", format_analyzer, dependencies=["file_info"]))

    # Parallel group: format_analysis, metadata, multiple hashers
    # (all depend on format_detection)
    parallelizable = [
        ("format_analysis", 0.05),
        ("metadata", 0.04),
        ("ssdeep", 0.06),
        ("tlsh", 0.05),
        ("impfuzzy", 0.04),
        ("telfhash", 0.05),
    ]

    for name, duration in parallelizable:

        def analyzer(d=duration, name=name) -> dict[str, Any]:
            time.sleep(d)
            return {"type": name}

        stages.append(AnalysisStage(name, analyzer, dependencies=["format_detection"]))

    # Detection stage (depends on metadata)
    def detection_analyzer() -> dict[str, Any]:
        time.sleep(0.03)
        return {"type": "detection"}

    stages.append(AnalysisStage("detection", detection_analyzer, dependencies=["metadata"]))

    return stages


def print_benchmark_report(results: list[BenchmarkResult]):
    """Print formatted benchmark report."""
    print("\n" + "=" * 80)
    print("PARALLEL PIPELINE BENCHMARK REPORT")
    print("=" * 80)

    for result in results:
        print(f"\n{result.name}")
        print("-" * 80)
        print(f"Sequential time: {result.sequential_time:.3f}s")
        print()
        print(f"{'Workers':<10} {'Time (s)':<12} {'Speedup':<12} {'Efficiency':<12}")
        print("-" * 80)

        for workers in sorted(result.parallel_times.keys()):
            time_val = result.parallel_times[workers]
            speedup = result.speedups[workers]
            efficiency = result.efficiency[workers]
            print(f"{workers:<10} {time_val:<12.3f} {speedup:<12.2f}x {efficiency:<12.2%}")

    # Summary and recommendations
    print("\n" + "=" * 80)
    print("SUMMARY AND RECOMMENDATIONS")
    print("=" * 80)

    # Best speedups
    print("\nBest Speedups:")
    for result in results:
        best_workers = max(result.speedups, key=result.speedups.get)
        best_speedup = result.speedups[best_workers]
        print(f"  {result.name}: {best_speedup:.2f}x with {best_workers} workers")

    # Efficiency analysis
    print("\nEfficiency Analysis:")
    print("  (Efficiency = Speedup / Workers, higher is better)")
    for result in results:
        best_eff_workers = max(result.efficiency, key=result.efficiency.get)
        best_eff = result.efficiency[best_eff_workers]
        print(f"  {result.name}: {best_eff:.1%} with {best_eff_workers} workers")

    # Recommendations
    print("\nRecommendations:")
    print("  1. I/O-bound workloads (file access, network): Use 4-8 workers")
    print("  2. CPU-bound workloads: Use workers = CPU cores (diminishing returns)")
    print("  3. Mixed workloads: Use 4 workers (default) for balanced performance")
    print("  4. Dependency chains: Limited parallelism, sequential may be better")
    print("  5. Realistic malware analysis: 4 workers provides best balance")
    print()
    print("  Default r2inspect configuration: max_workers=4 (optimal for I/O-bound)")
    print("=" * 80)


def main():
    """Run comprehensive benchmark suite."""
    print("Parallel Pipeline Performance Benchmark")
    print("=" * 80)
    print("Testing parallel execution performance across various scenarios...")

    worker_counts = [1, 2, 4, 8]
    results = []

    # Benchmark 1: I/O-bound stages
    results.append(
        benchmark_pipeline(
            name="I/O-Bound Stages (10 stages, 0.05s each)",
            stage_factory=create_io_bound_stages,
            num_stages=10,
            worker_counts=worker_counts,
            num_runs=3,
        )
    )

    # Benchmark 2: CPU-bound stages
    results.append(
        benchmark_pipeline(
            name="CPU-Bound Stages (8 stages)",
            stage_factory=create_cpu_bound_stages,
            num_stages=8,
            worker_counts=worker_counts,
            num_runs=3,
        )
    )

    # Benchmark 3: Mixed workload
    results.append(
        benchmark_pipeline(
            name="Mixed Workload (10 stages, I/O + CPU)",
            stage_factory=create_mixed_stages,
            num_stages=10,
            worker_counts=worker_counts,
            num_runs=3,
        )
    )

    # Benchmark 4: Dependency chain (limited parallelism)
    results.append(
        benchmark_pipeline(
            name="Dependency Chain (10 stages, sequential)",
            stage_factory=create_dependency_chain_stages,
            num_stages=10,
            worker_counts=worker_counts,
            num_runs=3,
        )
    )

    # Benchmark 5: Realistic malware analysis pipeline
    results.append(
        benchmark_pipeline(
            name="Realistic Malware Analysis Pipeline",
            stage_factory=create_realistic_malware_pipeline_stages,
            num_stages=9,  # Total stages created by factory
            worker_counts=worker_counts,
            num_runs=5,  # More runs for realistic scenario
        )
    )

    # Print comprehensive report
    print_benchmark_report(results)


if __name__ == "__main__":
    main()
