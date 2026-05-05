#!/usr/bin/env python3
"""
Generate box-and-whisker plots from evaluation results.

Usage:
    python plot_evaluation_results.py results.json
    python plot_evaluation_results.py results.json --output-dir my_plots
"""

import json
import argparse
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path

# Set style
sns.set_style("whitegrid")


def load_results(json_file: str) -> list[dict]:
    """Load evaluation results from JSON file."""
    print(f"Loading results from: {json_file}")
    
    with open(json_file, 'r') as f:
        results = json.load(f)
    
    print(f"✓ Loaded {len(results)} jobs")
    return results


def extract_job_stats(results: list[dict]) -> pd.DataFrame:
    """
    Extract per-job statistics.
    
    Returns:
        DataFrame with columns: job_id, cve_id, passed_count, total_tokens, eval_time
    """
    data = []
    
    for job in results:
        job_id = job.get("job_id", "unknown")
        cve_id = job.get("cve_id", "unknown")
        
        # Metrics passed
        metrics = job.get("metrics", [])
        total_metrics = len(metrics)
        passed_metrics = sum(1 for m in metrics if m.get("metric_score", 0) >= 0.6)
        
        # Token count
        total_tokens = job.get("token_usage", {}).get("total", 0)
        
        # Evaluation time
        eval_time = job.get("timing", {}).get("total_duration_seconds", 0)
        
        data.append({
            "job_id": job_id,
            "cve_id": cve_id,
            "passed_count": passed_metrics,
            "total_count": total_metrics,
            "total_tokens": total_tokens,
            "eval_time_seconds": eval_time
        })
    
    return pd.DataFrame(data)


def plot_box_whiskers(df: pd.DataFrame, output_dir: str = "plots"):
    """
    Generate 3 box-and-whisker plots.
    """
    Path(output_dir).mkdir(exist_ok=True)
    
    # Create labels for x-axis (truncated CVE IDs)
    job_labels = [cve[:20] + '...' if len(cve) > 20 else cve for cve in df['cve_id']]
    
    # ------------------------------
    # 1. Passed Metrics Count
    # ------------------------------
    print("\n Generating: Passed Metrics Count (box plot)")
    
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # Since we only have one run per job, we'll show individual points
    # with error bars showing the range from 0 to passed_count
    
    x_pos = range(len(df))
    passed_counts = df['passed_count'].values
    total_counts = df['total_count'].values
    
    # Create bar chart with individual points
    bars = ax.bar(x_pos, passed_counts, color='steelblue', alpha=0.7, edgecolor='black')
    
    # Add total count as a line
    ax.plot(x_pos, total_counts, 'r--', linewidth=2, label='Total Metrics', marker='o')
    
    # Color bars by pass rate
    for i, (bar, passed, total) in enumerate(zip(bars, passed_counts, total_counts)):
        pass_rate = passed / total if total > 0 else 0
        if pass_rate >= 0.8:
            bar.set_color('#2ECC71')  # Green
        elif pass_rate >= 0.6:
            bar.set_color('#F39C12')  # Orange
        else:
            bar.set_color('#E74C3C')  # Red
    
    # Add value labels on bars
    for i, (passed, total) in enumerate(zip(passed_counts, total_counts)):
        ax.text(i, passed + 0.5, f'{passed}/{total}', 
                ha='center', va='bottom', fontsize=9, weight='bold')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(job_labels, rotation=90, ha='right', fontsize=9)
    ax.set_xlabel('Job (CVE)', fontsize=12, weight='bold')
    ax.set_ylabel('Number of Metrics Passed', fontsize=12, weight='bold')
    ax.set_title('Metrics Passed per Job (Threshold ≥ 0.6)\n' +
                 f'Total: {len(df)} jobs, Average: {passed_counts.mean():.1f}/{total_counts.mean():.1f}',
                 fontsize=14, weight='bold', pad=20)
    ax.axhline(y=passed_counts.mean(), color='blue', linestyle=':', linewidth=2, label=f'Mean Passed: {passed_counts.mean():.1f}')
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/01_passed_metrics_count.png', dpi=300, bbox_inches='tight')
    plt.close()
    print(f" Saved: {output_dir}/01_passed_metrics_count.png")
    
    # ------------------------------
    # 2. Token Count Distribution
    # ------------------------------
    print("\n Generating: Token Count Distribution (box plot)")
    
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # Box plot
    bp = ax.boxplot([df['total_tokens'].values], 
                     labels=['All Jobs'],
                     widths=0.6,
                     patch_artist=True,
                     showmeans=True,
                     meanprops=dict(marker='D', markerfacecolor='red', markersize=10))
    
    # Color the box
    bp['boxes'][0].set_facecolor('lightblue')
    bp['boxes'][0].set_alpha(0.7)
    
    # Add individual job points
    x_jitter = np.random.normal(1, 0.04, size=len(df))  # Add jitter for visibility
    ax.scatter(x_jitter, df['total_tokens'], alpha=0.6, s=50, color='steelblue', edgecolor='black')
    
    # Statistics text
    stats_text = f"Mean: {df['total_tokens'].mean():,.0f}\n"
    stats_text += f"Median: {df['total_tokens'].median():,.0f}\n"
    stats_text += f"Std Dev: {df['total_tokens'].std():,.0f}\n"
    stats_text += f"Min: {df['total_tokens'].min():,.0f}\n"
    stats_text += f"Max: {df['total_tokens'].max():,.0f}"
    
    ax.text(1.3, df['total_tokens'].mean(), stats_text,
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
            fontsize=11, verticalalignment='center')
    
    ax.set_ylabel('Total Tokens', fontsize=12, weight='bold')
    ax.set_title(f'Token Usage Distribution Across {len(df)} Jobs',
                 fontsize=14, weight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/02_token_count_distribution.png', dpi=300, bbox_inches='tight')
    plt.close()
    print(f" Saved: {output_dir}/02_token_count_distribution.png")
    
    # ------------------------------
    # 3. Evaluation Time Distribution
    # ------------------------------
    print("\n Generating: Evaluation Time Distribution (box plot)")
    
    fig, ax = plt.subplots(figsize=(16, 8))
    
    # Box plot
    bp = ax.boxplot([df['eval_time_seconds'].values],
                     labels=['All Jobs'],
                     widths=0.6,
                     patch_artist=True,
                     showmeans=True,
                     meanprops=dict(marker='D', markerfacecolor='red', markersize=10))
    
    # Color the box
    bp['boxes'][0].set_facecolor('lightcoral')
    bp['boxes'][0].set_alpha(0.7)
    
    # Add individual job points
    x_jitter = np.random.normal(1, 0.04, size=len(df))
    ax.scatter(x_jitter, df['eval_time_seconds'], alpha=0.6, s=50, color='coral', edgecolor='black')
    
    # Statistics text
    stats_text = f"Mean: {df['eval_time_seconds'].mean():.2f}s\n"
    stats_text += f"Median: {df['eval_time_seconds'].median():.2f}s\n"
    stats_text += f"Std Dev: {df['eval_time_seconds'].std():.2f}s\n"
    stats_text += f"Min: {df['eval_time_seconds'].min():.2f}s\n"
    stats_text += f"Max: {df['eval_time_seconds'].max():.2f}s"
    
    ax.text(1.3, df['eval_time_seconds'].mean(), stats_text,
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8),
            fontsize=11, verticalalignment='center')
    
    ax.set_ylabel('Evaluation Time (seconds)', fontsize=12, weight='bold')
    ax.set_title(f'Evaluation Time Distribution Across {len(df)} Jobs',
                 fontsize=14, weight='bold', pad=20)
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/03_eval_time_distribution.png', dpi=300, bbox_inches='tight')
    plt.close()
    print(f" Saved: {output_dir}/03_eval_time_distribution.png")


def generate_summary_report(df: pd.DataFrame, output_dir: str = "plots"):
    """Generate text summary report."""
    print("\n" + "="*80)
    print("EVALUATION SUMMARY")
    print("="*80)
    
    print(f"\nTotal Jobs: {len(df)}")
    
    print(f"\n--- Metrics Passed ---")
    print(f"Average: {df['passed_count'].mean():.1f} / {df['total_count'].mean():.1f}")
    print(f"Median: {df['passed_count'].median():.0f} / {df['total_count'].median():.0f}")
    print(f"Min: {df['passed_count'].min()} / {df.loc[df['passed_count'].idxmin(), 'total_count']}")
    print(f"Max: {df['passed_count'].max()} / {df.loc[df['passed_count'].idxmax(), 'total_count']}")
    
    avg_pass_rate = (df['passed_count'] / df['total_count']).mean()
    print(f"Average Pass Rate: {avg_pass_rate:.1%}")
    
    print(f"\n--- Token Usage ---")
    print(f"Total: {df['total_tokens'].sum():,} tokens")
    print(f"Average per job: {df['total_tokens'].mean():,.0f} tokens")
    print(f"Median: {df['total_tokens'].median():,.0f} tokens")
    print(f"Std Dev: {df['total_tokens'].std():,.0f} tokens")
    
    print(f"\n--- Evaluation Time ---")
    print(f"Total: {df['eval_time_seconds'].sum():.2f}s ({df['eval_time_seconds'].sum()/60:.1f} min)")
    print(f"Average per job: {df['eval_time_seconds'].mean():.2f}s")
    print(f"Median: {df['eval_time_seconds'].median():.2f}s")
    print(f"Std Dev: {df['eval_time_seconds'].std():.2f}s")
    
    print("\n" + "="*80)
    
    # Save to file
    with open(f'{output_dir}/summary.txt', 'w') as f:
        f.write("="*80 + "\n")
        f.write("EVALUATION SUMMARY\n")
        f.write("="*80 + "\n\n")
        f.write(f"Total Jobs: {len(df)}\n\n")
        f.write(f"Metrics Passed:\n")
        f.write(f"  Average: {df['passed_count'].mean():.1f} / {df['total_count'].mean():.1f}\n")
        f.write(f"  Average Pass Rate: {avg_pass_rate:.1%}\n\n")
        f.write(f"Token Usage:\n")
        f.write(f"  Total: {df['total_tokens'].sum():,} tokens\n")
        f.write(f"  Average per job: {df['total_tokens'].mean():,.0f} tokens\n\n")
        f.write(f"Evaluation Time:\n")
        f.write(f"  Total: {df['eval_time_seconds'].sum():.2f}s\n")
        f.write(f"  Average per job: {df['eval_time_seconds'].mean():.2f}s\n")
    
    print(f"\n Summary saved to: {output_dir}/summary.txt")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate box-and-whisker plots from evaluation results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python plot_evaluation_results.py results.json
  
  # Specify output directory
  python plot_evaluation_results.py results.json --output-dir my_analysis
  
  # Multiple files (will process each separately)
  python plot_evaluation_results.py run1.json run2.json run3.json
"""
    )
    
    parser.add_argument(
        "json_file",
        help="Path to evaluation results JSON file"
    )
    
    parser.add_argument(
        "--output-dir",
        default="plots",
        help="Output directory for plots (default: plots)"
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("EVALUATION RESULTS VISUALIZATION")
    print("="*80)
    
    # Load results
    results = load_results(args.json_file)
    
    if not results:
        print("\nError: No results found in file")
        return 1
    
    # Extract statistics
    print("\n Extracting job statistics...")
    df = extract_job_stats(results)
    
    # Generate plots
    print(f"\n Generating plots in '{args.output_dir}/'...")
    plot_box_whiskers(df, args.output_dir)
    
    # Generate summary
    generate_summary_report(df, args.output_dir)
    
    print("\n" + "="*80)
    print(f"Complete! All plots saved to: {args.output_dir}/")
    print("="*80)
    
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())