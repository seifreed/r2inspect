#!/usr/bin/env python3
"""
r2inspect CLI - Command Line Interface
"""

import sys
import os
import json
import csv
import glob
from pathlib import Path
import click
import magic
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import pyfiglet

from .core import R2Inspector
from .utils.output import OutputFormatter
from .utils.logger import setup_logger
from .config import Config

console = Console()
logger = setup_logger()

def print_banner():
    """Print r2inspect banner"""
    banner = pyfiglet.figlet_format("r2inspect", font="slant")
    console.print(f"[bold blue]{banner}[/bold blue]")
    console.print("[bold]Advanced Malware Analysis Tool using Radare2[/bold]")
    console.print("[dim]Professional malware analysis powered by radare2[/dim]\n")

@click.command()
@click.argument('filename', type=click.Path(exists=True), required=False)
@click.option('-i', '--interactive', is_flag=True, help='Interactive mode')
@click.option('-j', '--json', 'output_json', is_flag=True, help='Full output analysis in JSON format')
@click.option('-c', '--csv', 'output_csv', is_flag=True, help='Output analysis in CSV format')
@click.option('-o', '--output', help='Output file path or directory for batch mode')
@click.option('-x', '--xor', help='Search XORed string')
@click.option('-s', '--strings', is_flag=True, help='Strings output')
@click.option('-v', '--verbose', is_flag=True, help='Verbose output')
@click.option('--config', help='Custom config file path')
@click.option('--yara', help='Custom YARA rules directory')
@click.option('--batch', '--directory', type=click.Path(exists=True, file_okay=False, dir_okay=True), 
              help='Process all files in directory (batch mode - recursive by default)')
@click.option('--extensions', 
              help='File extensions to process in batch mode (comma-separated). Default: auto-detect executable files')
@click.option('--list-yara', is_flag=True, help='List all available YARA rules and exit')
@click.option('--threads', default=10, help='Number of parallel threads for batch processing (default: 10)')
def main(filename, interactive, output_json, output_csv, output, xor, strings, 
         verbose, config, yara, batch, extensions, list_yara, threads):
    """r2inspect - Advanced malware analysis tool using radare2 and r2pipe"""
    
    try:
        # Handle --list-yara option first
        if list_yara:
            config_obj = Config(config)
            from .modules.yara_analyzer import YaraAnalyzer
            
            # Initialize a dummy r2 object
            class DummyR2:
                pass
            
            yara_analyzer = YaraAnalyzer(DummyR2(), config_obj)
            rules_path = yara or getattr(config_obj, 'yara_rules_path', 'r2inspect/rules/yara')
            
            available_rules = yara_analyzer.list_available_rules(rules_path)
            
            if available_rules:
                table = Table(title=f"Available YARA Rules in: {rules_path}")
                table.add_column("Rule File", style="cyan")
                table.add_column("Size", style="yellow")
                table.add_column("Path", style="green")
                
                for rule in available_rules:
                    size_kb = rule['size'] / 1024
                    table.add_row(
                        rule['name'], 
                        f"{size_kb:.1f} KB",
                        rule.get('relative_path', rule['path'])
                    )
                
                console.print(table)
                console.print(f"\n[green]Total: {len(available_rules)} YARA rule file(s) found[/green]")
                console.print("[blue]All these files will be automatically loaded when running analysis[/blue]")
            else:
                console.print(f"[yellow]No YARA rules found in: {rules_path}[/yellow]")
                console.print("[blue]You can place any .yar, .yara, .rule, or .rules files in this directory[/blue]")
            
            sys.exit(0)
        
        # Check if either filename or batch directory is provided
        if not filename and not batch:
            console.print("[red]Error: Must provide either a filename or --batch directory[/red]")
            sys.exit(1)
        
        # Allow JSON/CSV output with batch mode and output path
        if filename and batch:
            console.print("[red]Error: Cannot use both filename and --batch mode simultaneously[/red]")
            sys.exit(1)
        
        # Print banner if not in quiet mode
        if not output_json and not output_csv:
            print_banner()
        
        # Load configuration
        config_obj = Config(config)
        
        # Configure analysis options - enable all modules by default
        analysis_options = {
            'detect_packer': True,
            'detect_crypto': True,
            'detect_av': True,
            'full_analysis': True,
            'custom_yara': yara,
            'xor_search': xor
        }
        
        if batch:
            # Batch mode - recursive and auto-detect by default
            recursive = True  # Always recursive
            use_auto_detect = not extensions  # Auto-detect if no extensions specified
            
            # Set default output directory if not specified but JSON/CSV requested
            if (output_json or output_csv) and not output:
                output = "output"
            
            run_batch_analysis(batch, analysis_options, output_json, output_csv, output, 
                             recursive, extensions, verbose, config_obj, use_auto_detect, threads)
        else:
            # Single file mode
            inspector = R2Inspector(
                filename=filename,
                config=config_obj,
                verbose=verbose
            )
            
            if interactive:
                run_interactive_mode(inspector, analysis_options)
            elif strings:
                show_strings_only(inspector)
            else:
                # Auto-generate output filename for JSON/CSV if not specified
                if (output_json or output_csv) and not output:
                    import os
                    from pathlib import Path
                    
                    # Create output directory if it doesn't exist
                    output_dir = Path("output")
                    output_dir.mkdir(exist_ok=True)
                    
                    # Generate filename based on input file
                    input_path = Path(filename)
                    base_name = input_path.stem
                    
                    if output_json:
                        output = output_dir / f"{base_name}_analysis.json"
                    elif output_csv:
                        output = output_dir / f"{base_name}_analysis.csv"
                
                run_analysis(inspector, analysis_options, output_json, output_csv, output)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def run_analysis(inspector, options, output_json, output_csv, output_file):
    """Run complete analysis and display results"""
    
    # Only print status messages if not outputting JSON/CSV to stdout
    if not output_json and not output_csv:
        console.print("[bold green]Starting analysis...[/bold green]")
    elif (output_json or output_csv) and output_file:
        console.print("[bold green]Starting analysis...[/bold green]")
    
    # Perform analysis
    results = inspector.analyze(**options)
    
    # Format output
    formatter = OutputFormatter(results)
    
    if output_json:
        json_output = formatter.to_json()
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            console.print(f"[green]JSON results saved to: {output_file}[/green]")
        else:
            print(json_output)
    elif output_csv:
        csv_output = formatter.to_csv()
        if output_file:
            with open(output_file, 'w') as f:
                f.write(csv_output)
            console.print(f"[green]CSV results saved to: {output_file}[/green]")
        else:
            print(csv_output)
    else:
        # Display formatted results
        display_results(results)

def display_results(results):
    """Display analysis results in a formatted table"""
    
    # File Information
    if 'file_info' in results:
        file_info = results['file_info']
        table = Table(title="File Information", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in file_info.items():
            table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(table)
        console.print()
    
    # PE Information
    if 'pe_info' in results:
        pe_info = results['pe_info']
        table = Table(title="PE Analysis", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        for key, value in pe_info.items():
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(table)
        console.print()
    
    # Security Features
    if 'security' in results:
        security = results['security']
        table = Table(title="Security Features", show_header=True)
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="magenta")
        
        for key, value in security.items():
            status = "[green]✓[/green]" if value else "[red]✗[/red]"
            table.add_row(key.replace('_', ' ').title(), status)
        
        console.print(table)
        console.print()
    
    # SSDeep Information
    if 'ssdeep' in results:
        ssdeep_info = results['ssdeep']
        table = Table(title="SSDeep Fuzzy Hash", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if ssdeep_info.get('available'):
            table.add_row("Hash", ssdeep_info.get('ssdeep_hash', 'N/A'))
            table.add_row("Method", ssdeep_info.get('method_used', 'Unknown'))
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if ssdeep_info.get('error'):
                table.add_row("Error", ssdeep_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # TLSH Information
    if 'tlsh' in results:
        tlsh_info = results['tlsh']
        table = Table(title="TLSH Locality Sensitive Hash", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if tlsh_info.get('available'):
            # Binary TLSH
            binary_tlsh = tlsh_info.get('binary_tlsh')
            if binary_tlsh:
                table.add_row("Binary TLSH", binary_tlsh)
            else:
                table.add_row("Binary TLSH", "[red]Not Available[/red]")
            
            # Text section TLSH
            text_tlsh = tlsh_info.get('text_section_tlsh')
            if text_tlsh:
                table.add_row("Text Section TLSH", text_tlsh)
            else:
                table.add_row("Text Section TLSH", "[red]Not Available[/red]")
            
            # Function statistics
            stats = tlsh_info.get('stats', {})
            table.add_row("Functions Analyzed", str(stats.get('functions_analyzed', 0)))
            table.add_row("Functions with TLSH", str(stats.get('functions_with_tlsh', 0)))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if tlsh_info.get('error'):
                table.add_row("Error", tlsh_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Telfhash Information (ELF only)
    if 'telfhash' in results:
        telfhash_info = results['telfhash']
        table = Table(title="Telfhash (ELF Symbol Hash)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if telfhash_info.get('available'):
            if telfhash_info.get('is_elf'):
                # Telfhash value
                telfhash_value = telfhash_info.get('telfhash')
                if telfhash_value:
                    table.add_row("Telfhash", telfhash_value)
                else:
                    table.add_row("Telfhash", "[red]Not Available[/red]")
                
                # Symbol statistics
                table.add_row("Total Symbols", str(telfhash_info.get('symbol_count', 0)))
                table.add_row("Filtered Symbols", str(telfhash_info.get('filtered_symbols', 0)))
                
                # Show some symbols used
                symbols_used = telfhash_info.get('symbols_used', [])
                if symbols_used:
                    symbols_preview = ', '.join(symbols_used[:5])
                    if len(symbols_used) > 5:
                        symbols_preview += f" (+ {len(symbols_used) - 5} more)"
                    table.add_row("Symbols Used", symbols_preview)
                
                table.add_row("Status", "[green]✓ Available[/green]")
            else:
                table.add_row("Status", "[yellow]⚠ Not ELF File[/yellow]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if telfhash_info.get('error'):
                table.add_row("Error", telfhash_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Rich Header Information (PE only)
    if 'rich_header' in results:
        rich_header_info = results['rich_header']
        table = Table(title="Rich Header (PE Build Environment)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if rich_header_info.get('available'):
            if rich_header_info.get('is_pe'):
                # XOR Key and Checksum
                xor_key = rich_header_info.get('xor_key')
                if xor_key is not None:
                    table.add_row("XOR Key", f"0x{xor_key:08X}")
                
                checksum = rich_header_info.get('checksum')
                if checksum is not None:
                    table.add_row("Checksum", f"0x{checksum:08X}")
                
                # RichPE Hash
                richpe_hash = rich_header_info.get('richpe_hash')
                if richpe_hash:
                    table.add_row("RichPE Hash", richpe_hash)
                
                # Compiler statistics
                compilers = rich_header_info.get('compilers', [])
                table.add_row("Compiler Entries", str(len(compilers)))
                
                # Show compiler details
                if compilers:
                    compiler_summary = []
                    for compiler in compilers[:5]:  # Show first 5
                        name = compiler.get('compiler_name', 'Unknown')
                        count = compiler.get('count', 0)
                        build = compiler.get('build_number', 0)
                        compiler_summary.append(f"{name} (Build {build}): {count}")
                    
                    if len(compilers) > 5:
                        compiler_summary.append(f"... and {len(compilers) - 5} more")
                    
                    table.add_row("Compilers Used", '\n'.join(compiler_summary))
                
                table.add_row("Status", "[green]✓ Available[/green]")
            else:
                table.add_row("Status", "[yellow]⚠ Not PE File[/yellow]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if rich_header_info.get('error'):
                table.add_row("Error", rich_header_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Impfuzzy Information (PE only)
    if 'impfuzzy' in results:
        impfuzzy_info = results['impfuzzy']
        table = Table(title="Impfuzzy (PE Import Fuzzy Hash)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if impfuzzy_info.get('available'):
            # Impfuzzy Hash
            impfuzzy_hash = impfuzzy_info.get('impfuzzy_hash')
            if impfuzzy_hash:
                table.add_row("Impfuzzy Hash", impfuzzy_hash)
            
            # Import statistics
            import_count = impfuzzy_info.get('import_count', 0)
            table.add_row("Total Imports", str(import_count))
            
            dll_count = impfuzzy_info.get('dll_count', 0)
            table.add_row("DLL Count", str(dll_count))
            
            # Show sample imports
            imports_processed = impfuzzy_info.get('imports_processed', [])
            if imports_processed:
                sample_imports = imports_processed[:10]  # Show first 10
                if len(imports_processed) > 10:
                    sample_imports.append(f"... and {len(imports_processed) - 10} more")
                table.add_row("Sample Imports", '\n'.join(sample_imports))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if impfuzzy_info.get('error'):
                table.add_row("Error", impfuzzy_info.get('error', 'Unknown error'))
            if not impfuzzy_info.get('library_available'):
                table.add_row("Note", "pyimpfuzzy library not installed")
        
        console.print(table)
        console.print()
    
    # CCBHash Information (Control Flow Graph Hash)
    if 'ccbhash' in results:
        ccbhash_info = results['ccbhash']
        table = Table(title="CCBHash (Control Flow Graph Hash)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if ccbhash_info.get('available'):
            # Binary CCBHash
            binary_hash = ccbhash_info.get('binary_ccbhash')
            if binary_hash:
                # Show full hash for CCBHash (it's important for identification)
                table.add_row("Binary CCBHash", binary_hash)
            
            # Function statistics
            total_functions = ccbhash_info.get('total_functions', 0)
            table.add_row("Total Functions", str(total_functions))
            
            analyzed_functions = ccbhash_info.get('analyzed_functions', 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))
            
            unique_hashes = ccbhash_info.get('unique_hashes', 0)
            table.add_row("Unique CCBHashes", str(unique_hashes))
            
            # Similar functions
            similar_functions = ccbhash_info.get('similar_functions', [])
            if similar_functions:
                table.add_row("Similar Function Groups", str(len(similar_functions)))
                # Show the largest group
                largest_group = similar_functions[0] if similar_functions else None
                if largest_group:
                    table.add_row("Largest Similar Group", f"{largest_group['count']} functions")
                    # Show sample function names from the largest group
                    sample_funcs = largest_group['functions'][:3]
                    if len(largest_group['functions']) > 3:
                        sample_funcs.append(f"... and {len(largest_group['functions']) - 3} more")
                    table.add_row("Sample Functions", ', '.join(sample_funcs))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if ccbhash_info.get('error'):
                table.add_row("Error", ccbhash_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Binlex Information (N-gram Lexical Analysis)
    if 'binlex' in results:
        binlex_info = results['binlex']
        table = Table(title="Binlex (N-gram Lexical Analysis)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        if binlex_info.get('available'):
            # Basic statistics
            total_functions = binlex_info.get('total_functions', 0)
            table.add_row("Total Functions", str(total_functions))
            
            analyzed_functions = binlex_info.get('analyzed_functions', 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))
            
            # N-gram sizes analyzed
            ngram_sizes = binlex_info.get('ngram_sizes', [])
            table.add_row("N-gram Sizes", ', '.join(map(str, ngram_sizes)))
            
            # Unique signatures for each n-gram size
            unique_signatures = binlex_info.get('unique_signatures', {})
            for n in ngram_sizes:
                if n in unique_signatures:
                    table.add_row(f"Unique {n}-gram Signatures", str(unique_signatures[n]))
            
            # Similar functions
            similar_functions = binlex_info.get('similar_functions', {})
            for n in ngram_sizes:
                if n in similar_functions and similar_functions[n]:
                    groups = similar_functions[n]
                    table.add_row(f"Similar {n}-gram Groups", str(len(groups)))
                    # Show largest group
                    if groups:
                        largest_group = groups[0]
                        table.add_row(f"Largest {n}-gram Group", f"{largest_group['count']} functions")
            
            # Binary signatures
            binary_signature = binlex_info.get('binary_signature', {})
            for n in ngram_sizes:
                if n in binary_signature:
                    sig = binary_signature[n]
                    # Show complete signature for Binlex (important for identification)
                    table.add_row(f"Binary {n}-gram Signature", sig)
            
            # Top n-grams
            top_ngrams = binlex_info.get('top_ngrams', {})
            for n in ngram_sizes:
                if n in top_ngrams and top_ngrams[n]:
                    # Show top 3 most common n-grams, clean up encoding issues
                    top_3 = top_ngrams[n][:3]
                    ngram_strs = []
                    for ngram, count in top_3:
                        # Clean up any HTML entities and normalize whitespace
                        clean_ngram = ngram.replace('&nbsp;', ' ').replace('&amp;', '&').strip()
                        # Limit length to avoid very long display
                        if len(clean_ngram) > 50:
                            clean_ngram = clean_ngram[:47] + "..."
                        ngram_strs.append(f"• {clean_ngram} ({count})")
                    table.add_row(f"Top {n}-grams", '\n'.join(ngram_strs))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if binlex_info.get('error'):
                table.add_row("Error", binlex_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Binbloom Information (Bloom Filter Analysis)
    if 'binbloom' in results:
        binbloom_info = results['binbloom']
        table = Table(title="Binbloom (Bloom Filter Analysis)", show_header=True, width=120)
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", width=90, overflow="fold")
        
        if binbloom_info.get('available'):
            # Basic statistics
            total_functions = binbloom_info.get('total_functions', 0)
            table.add_row("Total Functions", str(total_functions))
            
            analyzed_functions = binbloom_info.get('analyzed_functions', 0)
            table.add_row("Analyzed Functions", str(analyzed_functions))
            
            # Bloom filter configuration
            capacity = binbloom_info.get('capacity', 0)
            error_rate = binbloom_info.get('error_rate', 0.0)
            table.add_row("Bloom Filter Capacity", str(capacity))
            table.add_row("False Positive Rate", f"{error_rate:.4f} ({error_rate*100:.2f}%)")
            
            # Unique signatures
            unique_signatures = binbloom_info.get('unique_signatures', 0)
            diversity_ratio = (unique_signatures / analyzed_functions * 100) if analyzed_functions > 0 else 0
            table.add_row("Unique Function Signatures", f"{unique_signatures} ({diversity_ratio:.1f}% diversity)")
            
            # Function signatures details
            function_signatures = binbloom_info.get('function_signatures', {})
            if function_signatures:
                # Calculate instruction statistics
                total_instructions = sum(sig.get('instruction_count', 0) for sig in function_signatures.values())
                avg_instructions = total_instructions / len(function_signatures) if function_signatures else 0
                
                unique_instructions = sum(sig.get('unique_instructions', 0) for sig in function_signatures.values())
                avg_unique = unique_instructions / len(function_signatures) if function_signatures else 0
                
                table.add_row("Avg Instructions/Function", f"{avg_instructions:.1f}")
                table.add_row("Avg Unique Instructions", f"{avg_unique:.1f}")
            
            # Similar functions
            similar_functions = binbloom_info.get('similar_functions', [])
            if similar_functions:
                table.add_row("Similar Function Groups", str(len(similar_functions)))
                
                # Show details for each group
                for i, group in enumerate(similar_functions[:3]):  # Show first 3 groups
                    group_size = group.get('count', 0)
                    group_signature = group.get('signature', '')
                    
                    # Format signature for better display
                    if len(group_signature) > 32:
                        group_sig = group_signature[:32] + "..."
                    else:
                        group_sig = group_signature
                    
                    table.add_row(f"Group {i+1} Size", f"{group_size} functions")
                    table.add_row(f"Group {i+1} Signature", group_sig)
                    
                    # Show sample functions from this group
                    if group.get('functions'):
                        sample_funcs = group['functions'][:5]  # Show first 5
                        func_display = []
                        for func in sample_funcs:
                            # Truncate very long function names
                            func_name = func if len(func) <= 30 else func[:27] + "..."
                            func_display.append(f"• {func_name}")
                        
                        if len(group['functions']) > 5:
                            func_display.append(f"• ... and {len(group['functions']) - 5} more")
                        
                        table.add_row(f"Group {i+1} Functions", '\n'.join(func_display))
                
                if len(similar_functions) > 3:
                    table.add_row("Additional Groups", f"... and {len(similar_functions) - 3} more groups")
            else:
                table.add_row("Similar Function Groups", "0 (all functions unique)")
            
            # Binary-wide signature
            binary_signature = binbloom_info.get('binary_signature')
            if binary_signature:
                # Show the signature in a more readable format
                if len(binary_signature) > 64:
                    # Split long signature into multiple lines for better readability
                    sig_parts = []
                    for i in range(0, min(len(binary_signature), 128), 32):
                        sig_parts.append(binary_signature[i:i+32])
                    if len(binary_signature) > 128:
                        sig_parts.append("...")
                    sig_display = '\n'.join(sig_parts)
                else:
                    sig_display = binary_signature
                table.add_row("Binary Bloom Signature", sig_display)
            
            # Bloom filter statistics
            bloom_stats = binbloom_info.get('bloom_stats', {})
            if bloom_stats:
                avg_fill_rate = bloom_stats.get('average_fill_rate', 0.0)
                table.add_row("Average Fill Rate", f"{avg_fill_rate:.4f} ({avg_fill_rate*100:.2f}%)")
                
                total_filters = bloom_stats.get('total_filters', 0)
                table.add_row("Total Bloom Filters", str(total_filters))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if binbloom_info.get('error'):
                table.add_row("Error", binbloom_info.get('error', 'Unknown error'))
            elif not binbloom_info.get('library_available', True):
                table.add_row("Error", "pybloom-live library not installed")
                table.add_row("Install Command", "pip install pybloom-live")
        
        console.print(table)
        
        # Show additional details if there are unique signatures
        if binbloom_info.get('available') and binbloom_info.get('unique_signatures', 0) > 1:
            console.print("\n[bold cyan]Binbloom Signature Details:[/bold cyan]")
            
            # Show top unique function signatures
            function_signatures = binbloom_info.get('function_signatures', {})
            signatures_by_hash = {}
            
            for func_name, sig_data in function_signatures.items():
                sig_hash = sig_data.get('signature', '')
                if sig_hash not in signatures_by_hash:
                    signatures_by_hash[sig_hash] = []
                signatures_by_hash[sig_hash].append(func_name)
            
            # Show unique signatures (limit to first 5)
            unique_sigs = list(signatures_by_hash.keys())[:5]
            for i, sig_hash in enumerate(unique_sigs):
                funcs = signatures_by_hash[sig_hash]
                console.print(f"[yellow]Signature {i+1}:[/yellow] {sig_hash[:64]}{'...' if len(sig_hash) > 64 else ''}")
                console.print(f"[dim]Functions ({len(funcs)}):[/dim] {', '.join(funcs[:3])}{'...' if len(funcs) > 3 else ''}")
                console.print()
        
        console.print()
    
    # SimHash Information (Similarity Hashing)
    if 'simhash' in results:
        simhash_info = results['simhash']
        table = Table(title="SimHash (Similarity Hashing)", show_header=True, width=120)
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", width=90, overflow="fold")
        
        if simhash_info.get('available'):
            # Feature statistics
            feature_stats = simhash_info.get('feature_stats', {})
            total_features = feature_stats.get('total_features', 0)
            total_strings = feature_stats.get('total_strings', 0)
            total_opcodes = feature_stats.get('total_opcodes', 0)
            
            table.add_row("Total Features", str(total_features))
            table.add_row("String Features", str(total_strings))
            table.add_row("Opcode Features", str(total_opcodes))
            
            # Feature diversity
            feature_diversity = feature_stats.get('feature_diversity', 0.0)
            table.add_row("Feature Diversity", f"{feature_diversity:.3f}")
            
            # Combined SimHash (main binary signature)
            combined_simhash = simhash_info.get('combined_simhash')
            if combined_simhash:
                hash_hex = combined_simhash.get('hex', '')
                # Show full SimHash with line breaks for better readability
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Binary SimHash", hash_display)
                table.add_row("Combined Features", str(combined_simhash.get('feature_count', 0)))
            
            # Strings-only SimHash
            strings_simhash = simhash_info.get('strings_simhash')
            if strings_simhash:
                hash_hex = strings_simhash.get('hex', '')
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Strings SimHash", hash_display)
            
            # Opcodes-only SimHash
            opcodes_simhash = simhash_info.get('opcodes_simhash')
            if opcodes_simhash:
                hash_hex = opcodes_simhash.get('hex', '')
                if len(hash_hex) > 32:
                    hash_display = f"{hash_hex[:32]}\n{hash_hex[32:]}"
                else:
                    hash_display = hash_hex
                table.add_row("Opcodes SimHash", hash_display)
            
            # Function-level analysis
            function_simhashes = simhash_info.get('function_simhashes', {})
            if function_simhashes:
                total_functions = simhash_info.get('total_functions', 0)
                analyzed_functions = simhash_info.get('analyzed_functions', 0)
                
                table.add_row("Total Functions", str(total_functions))
                table.add_row("Analyzed Functions", str(analyzed_functions))
                
                # Similar function groups
                similarity_groups = simhash_info.get('similarity_groups', [])
                if similarity_groups:
                    table.add_row("Similar Function Groups", str(len(similarity_groups)))
                    
                    # Show details for largest groups
                    for i, group in enumerate(similarity_groups[:3]):
                        group_size = group.get('count', 0)
                        group_hash = group.get('representative_hash', '')
                        # Show more of the hash for better identification
                        if len(group_hash) > 24:
                            hash_display = f"{group_hash[:24]}...{group_hash[-8:]}"
                        else:
                            hash_display = group_hash
                        
                        table.add_row(f"Group {i+1} Size", f"{group_size} functions")
                        table.add_row(f"Group {i+1} Hash", hash_display)
                        
                        # Show sample functions
                        if group.get('functions'):
                            sample_funcs = group['functions'][:5]
                            func_display = []
                            for func in sample_funcs:
                                func_name = func if len(func) <= 30 else func[:27] + "..."
                                func_display.append(f"• {func_name}")
                            
                            if len(group['functions']) > 5:
                                func_display.append(f"• ... and {len(group['functions']) - 5} more")
                            
                            table.add_row(f"Group {i+1} Functions", '\n'.join(func_display))
                    
                    if len(similarity_groups) > 3:
                        table.add_row("Additional Groups", f"... and {len(similarity_groups) - 3} more groups")
                else:
                    table.add_row("Similar Function Groups", "0 (all functions unique)")
            
            # Most common features
            most_common = feature_stats.get('most_common_features', [])
            if most_common:
                top_features = []
                for feature, count in most_common[:5]:
                    # Clean feature name for display
                    clean_feature = feature.replace('STR:', '').replace('OP:', '').replace('OPTYPE:', '')
                    if len(clean_feature) > 40:
                        clean_feature = clean_feature[:37] + "..."
                    top_features.append(f"• {clean_feature} ({count})")
                
                table.add_row("Top Features", '\n'.join(top_features))
            
            table.add_row("Status", "[green]✓ Available[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if simhash_info.get('error'):
                table.add_row("Error", simhash_info.get('error', 'Unknown error'))
            elif not simhash_info.get('library_available', True):
                table.add_row("Error", "simhash library not installed")
                table.add_row("Install Command", "pip install simhash")
        
        console.print(table)
        console.print()
    
    # BinDiff Information (Binary Comparison Features)
    if 'bindiff' in results:
        bindiff_info = results['bindiff']
        table = Table(title="BinDiff (Binary Comparison Features)", show_header=True)
        table.add_column("Property", style="cyan", width=25)
        table.add_column("Value", style="yellow", no_wrap=False)
        
        if bindiff_info.get('comparison_ready'):
            # File information
            table.add_row("Filename", bindiff_info.get('filename', 'Unknown'))
            
            # Structural features
            structural = bindiff_info.get('structural_features', {})
            if structural:
                table.add_row("File Type", structural.get('file_type', 'Unknown'))
                table.add_row("Architecture", f"{structural.get('architecture', 'Unknown')} ({structural.get('bits', 'Unknown')} bits)")
                table.add_row("File Size", f"{structural.get('file_size', 0):,} bytes")
                table.add_row("Sections", str(structural.get('section_count', 0)))
                if structural.get('section_names'):
                    section_names = structural['section_names']
                    if len(section_names) <= 7:
                        # Show all sections if 7 or fewer
                        table.add_row("Section Names", ", ".join(section_names))
                    else:
                        # Show first 5 and indicate there are more
                        displayed = section_names[:5]
                        remaining = len(section_names) - 5
                        table.add_row("Section Names", f"{', '.join(displayed)}\n... and {remaining} more")
                table.add_row("Imports", str(structural.get('import_count', 0)))
                table.add_row("Exports", str(structural.get('export_count', 0)))
            
            # Function features
            function_features = bindiff_info.get('function_features', {})
            if function_features:
                table.add_row("Functions", str(function_features.get('function_count', 0)))
                if function_features.get('cfg_features'):
                    cfg_count = len(function_features['cfg_features'])
                    table.add_row("CFG Analysis", f"{cfg_count} functions analyzed")
            
            # String features  
            string_features = bindiff_info.get('string_features', {})
            if string_features:
                table.add_row("Strings", str(string_features.get('total_strings', 0)))
                if string_features.get('categorized_strings'):
                    categories = list(string_features['categorized_strings'].keys())[:3]
                    table.add_row("String Types", ", ".join(categories))
            
            # Signatures
            signatures = bindiff_info.get('signatures', {})
            if signatures:
                structural_hash = signatures.get('structural', 'N/A')
                function_hash = signatures.get('function', 'N/A')
                string_hash = signatures.get('string', 'N/A')
                
                # Show full hash or N/A if not available
                table.add_row("Structural Hash", structural_hash if structural_hash != 'N/A' else 'Not Available')
                table.add_row("Function Hash", function_hash if function_hash != 'N/A' else 'Not Available')
                table.add_row("String Hash", string_hash if string_hash != 'N/A' else 'Not Available')
            
            table.add_row("Status", "[green]✓ Comparison Ready[/green]")
        else:
            table.add_row("Status", "[red]✗ Not Available[/red]")
            if bindiff_info.get('error'):
                table.add_row("Error", bindiff_info.get('error', 'Unknown error'))
        
        console.print(table)
        console.print()
    
    # Function Analysis (MACHOC)
    if 'functions' in results:
        functions_info = results['functions']
        table = Table(title="Function Analysis (MACHOC)", show_header=True)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="yellow")
        
        table.add_row("Total Functions", str(functions_info.get('total_functions', 0)))
        
        machoc_hashes = functions_info.get('machoc_hashes', {})
        unique_hashes = len(set(machoc_hashes.values())) if machoc_hashes else 0
        table.add_row("Unique MACHOC Hashes", str(unique_hashes))
        
        # Calculate duplicates
        if machoc_hashes:
            hash_counts = {}
            for func_name, machoc_hash in machoc_hashes.items():
                hash_counts[machoc_hash] = hash_counts.get(machoc_hash, 0) + 1
            duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
            table.add_row("Duplicate Functions", str(duplicates))
        
        console.print(table)
        console.print()
    
    # Suspicious Indicators
    if 'indicators' in results and results['indicators']:
        table = Table(title="Suspicious Indicators", show_header=True)
        table.add_column("Type", style="red")
        table.add_column("Description", style="yellow")
        table.add_column("Severity", style="magenta")
        
        for indicator in results['indicators']:
            table.add_row(
                indicator.get('type', 'Unknown'),
                indicator.get('description', 'N/A'),
                indicator.get('severity', 'Unknown')
            )
        
        console.print(table)
        console.print()

def show_strings_only(inspector):
    """Show only strings analysis"""
    console.print("[bold green]Extracting strings...[/bold green]")
    strings = inspector.get_strings()
    
    for string in strings:
        console.print(string)

def run_interactive_mode(inspector, options):
    """Run interactive analysis mode"""
    console.print("[bold blue]Interactive Mode - r2inspect[/bold blue]")
    console.print("Available commands:")
    console.print("  analyze - Run full analysis")
    console.print("  strings - Show strings")
    console.print("  info    - Show file info")
    console.print("  pe      - Show PE info")
    console.print("  imports - Show imports")
    console.print("  exports - Show exports")
    console.print("  sections - Show sections")
    console.print("  quit    - Exit")
    
    while True:
        try:
            cmd = input("\nr2inspect> ").strip().lower()
            
            if cmd == 'quit' or cmd == 'exit':
                break
            elif cmd == 'analyze':
                results = inspector.analyze(**options)
                display_results(results)
            elif cmd == 'strings':
                show_strings_only(inspector)
            elif cmd == 'info':
                info = inspector.get_file_info()
                formatter = OutputFormatter({'file_info': info})
                console.print(formatter.format_table(info, "File Information"))
            elif cmd == 'pe':
                pe_info = inspector.get_pe_info()
                formatter = OutputFormatter({'pe_info': pe_info})
                console.print(formatter.format_table(pe_info, "PE Information"))
            elif cmd == 'imports':
                imports = inspector.get_imports()
                for imp in imports:
                    console.print(imp)
            elif cmd == 'exports':
                exports = inspector.get_exports()
                for exp in exports:
                    console.print(exp)
            elif cmd == 'sections':
                sections = inspector.get_sections()
                formatter = OutputFormatter({'sections': sections})
                console.print(formatter.format_sections(sections))
            elif cmd == 'help':
                console.print("Available commands: analyze, strings, info, pe, imports, exports, sections, quit")
            elif cmd == '':
                continue
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
                console.print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            break
        except EOFError:
            break
    
    console.print("[yellow]Exiting interactive mode...[/yellow]")

def find_executable_files_by_magic(directory, recursive=False, verbose=False):
    """Find executable files using magic bytes detection (PE, ELF, Mach-O, etc.)"""
    executable_files = []
    directory = Path(directory)
    
    # Initialize magic
    try:
        mime_magic = magic.Magic(mime=True)
        desc_magic = magic.Magic()
    except Exception as e:
        console.print(f"[red]Error initializing magic: {e}[/red]")
        console.print("[yellow]Falling back to file extension detection[/yellow]")
        return []
    
    # Executable file signatures and descriptions to look for
    executable_signatures = [
        'application/x-dosexec',        # PE executables (Windows)
        'application/x-msdownload',     # Windows executables
        'application/x-executable',     # Generic executables
        'application/x-sharedlib',      # Shared libraries
        'application/x-pie-executable', # Position Independent Executables
        'application/octet-stream'      # Sometimes executables show as this
    ]
    
    executable_descriptions = [
        'PE32 executable',              # Windows PE32
        'PE32+ executable',             # Windows PE32+
        'MS-DOS executable',            # DOS executables
        'Microsoft Portable Executable', # Microsoft PE
        'ELF',                          # Linux/Unix ELF
        'Mach-O',                       # macOS Mach-O
        'executable',                   # Generic executable
        'shared object',                # Shared libraries (.so, .dll)
        'dynamically linked'            # Dynamically linked executables
    ]
    
    # Get all files
    if recursive:
        all_files = directory.rglob('*')
    else:
        all_files = directory.glob('*')
    
    # Filter to regular files only
    regular_files = [f for f in all_files if f.is_file()]
    
    if verbose:
        console.print(f"[blue]Scanning {len(regular_files)} files for executable signatures...[/blue]")
    
    for file_path in regular_files:
        try:
            # Skip very small files (less than 64 bytes - minimum PE size)
            if file_path.stat().st_size < 64:
                continue
                
            # Check MIME type
            mime_type = mime_magic.from_file(str(file_path))
            
            # Check file description
            description = desc_magic.from_file(str(file_path))
            
            # Check if it's an executable file
            is_executable = False
            
            # Check MIME type
            if any(sig in mime_type.lower() for sig in executable_signatures):
                is_executable = True
            
            # Check description
            if any(desc.lower() in description.lower() for desc in executable_descriptions):
                is_executable = True
            
            # Additional checks for specific executable formats
            if not is_executable:
                is_executable = check_executable_signature(file_path)
            
            if is_executable:
                executable_files.append(file_path)
                if verbose:
                    console.print(f"[green]✓[/green] Executable file detected: {file_path.name} ({description})")
            elif verbose and file_path.suffix.lower() in ['.exe', '.dll', '.scr', '.com', '.so', '.dylib', '.app']:
                # Show files with executable extensions that weren't detected as executables
                console.print(f"[yellow]?[/yellow] {file_path.name} ({description})")
                
        except Exception as e:
            if verbose:
                console.print(f"[red]Error checking {file_path.name}: {e}[/red]")
            continue
    
    console.print(f"[green]Found {len(executable_files)} executable files[/green]")
    return executable_files

def check_executable_signature(file_path):
    """Check for executable signatures in file header (PE, ELF, Mach-O)"""
    try:
        with open(file_path, 'rb') as f:
            # Read first 64 bytes
            header = f.read(64)
            if len(header) < 4:
                return False
            
            # Check for various executable signatures
            
            # PE (Windows) - MZ header
            if header[:2] == b'MZ':
                if len(header) >= 64:
                    try:
                        pe_offset = int.from_bytes(header[60:64], byteorder='little')
                        f.seek(pe_offset)
                        pe_signature = f.read(4)
                        if pe_signature == b'PE\x00\x00':
                            return True
                    except:
                        pass
                return True  # MZ header is good enough indication
            
            # ELF (Linux/Unix) - 0x7F followed by 'ELF'
            if header[:4] == b'\x7fELF':
                return True
            
            # Mach-O (macOS) - Various magic numbers
            mach_o_magics = [
                b'\xfe\xed\xfa\xce',  # 32-bit big endian
                b'\xce\xfa\xed\xfe',  # 32-bit little endian
                b'\xfe\xed\xfa\xcf',  # 64-bit big endian
                b'\xcf\xfa\xed\xfe',  # 64-bit little endian
                b'\xca\xfe\xba\xbe',  # Universal binary
            ]
            
            for magic in mach_o_magics:
                if header[:4] == magic:
                    return True
            
            # Check for script shebangs (#!/bin/sh, #!/usr/bin/python, etc.)
            if header[:2] == b'#!':
                return True
                
            return False
            
    except Exception:
        return False

def run_batch_analysis(batch_dir, options, output_json, output_csv, output_dir, 
                      recursive, extensions, verbose, config_obj, auto_detect, threads=10):
    """Run batch analysis on multiple files in a directory"""
    
    # Find files to process
    files_to_process = []
    batch_path = Path(batch_dir)
    
    if auto_detect:
        # Auto-detect executable files using magic bytes (default behavior)
        console.print("[blue]Auto-detecting executable files (default behavior)...[/blue]")
        files_to_process = find_executable_files_by_magic(batch_path, recursive, verbose)
    else:
        # Use user-specified file extensions
        console.print(f"[blue]Searching for files with extensions: {extensions}[/blue]")
        ext_list = [ext.strip().lower() for ext in extensions.split(',')]
        
        if recursive:
            # Recursive search
            for ext in ext_list:
                pattern = f"**/*.{ext}"
                files_to_process.extend(batch_path.glob(pattern))
        else:
            # Non-recursive search
            for ext in ext_list:
                pattern = f"*.{ext}"
                files_to_process.extend(batch_path.glob(pattern))
    
    if not files_to_process:
        if auto_detect:
            console.print("[yellow]No executable files detected in the directory[/yellow]")
            console.print("[dim]Tip: Files might not be executable format or may be corrupted[/dim]")
        else:
            console.print(f"[yellow]No files found with extensions: {extensions}[/yellow]")
            console.print("[dim]Tip: Use without --extensions for auto-detection[/dim]")
        return
    
    console.print(f"[bold green]Found {len(files_to_process)} files to process[/bold green]")
    console.print(f"[blue]Using {threads} parallel threads[/blue]")
    
    # Suppress logging during batch processing for cleaner output
    if not verbose:
        import logging
        logging.getLogger('r2inspect.core').setLevel(logging.WARNING)
        logging.getLogger('r2inspect.modules.yara_analyzer').setLevel(logging.WARNING)
        logging.getLogger('r2inspect.modules.compiler_detector').setLevel(logging.WARNING)
    
    # Setup output directory
    if output_dir:
        output_path = Path(output_dir)
        if not output_path.exists():
            output_path.mkdir(parents=True, exist_ok=True)
    elif output_json or output_csv:
        # Default output directory when formats are specified
        output_path = Path("output")
        output_path.mkdir(exist_ok=True)
    else:
        # Fallback directory when no formats specified
        output_path = Path("r2inspect_batch_results")
        output_path.mkdir(exist_ok=True)
    
    # Results storage
    all_results = {}
    failed_files = []
    
    # Start timing
    import time
    start_time = time.time()
    
    # Process files with parallel threads
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading
    
    # Thread-safe data structures
    results_lock = threading.Lock()
    progress_lock = threading.Lock()
    
    def process_single_file(file_path):
        """Process a single file - thread-safe function"""
        try:
            # Initialize inspector for current file with minimal logging
            # Create a separate console for this thread to avoid Rich conflicts
            from rich.console import Console
            thread_console = Console(quiet=True)  # Quiet to avoid conflicts
            
            inspector = R2Inspector(
                filename=str(file_path),
                config=config_obj,
                verbose=False  # Always disable verbose for batch to reduce noise
            )
            
            # Perform analysis with batch mode flag to disable progress
            analysis_options = {**options, 'batch_mode': True}
            results = inspector.analyze(**analysis_options)
            results['filename'] = str(file_path)
            results['relative_path'] = str(file_path.relative_to(batch_path))
            
            # Save individual JSON files only for JSON mode (not CSV-only mode)
            if output_json:
                formatter = OutputFormatter(results)
                json_output = formatter.to_json()
                json_file = output_path / f"{file_path.stem}_analysis.json"
                with open(json_file, 'w') as f:
                    f.write(json_output)
            
            return file_path, results, None
            
        except Exception as e:
            return file_path, None, str(e)
    
    # Process files in parallel with Rich progress bar
    from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, TimeRemainingColumn
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        # Create progress task
        task = progress.add_task("Processing files...", total=len(files_to_process))
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_file = {executor.submit(process_single_file, file_path): file_path 
                             for file_path in files_to_process}
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                file_path, results, error = future.result()
                
                # Update progress thread-safely
                with progress_lock:
                    completed_count += 1
                    progress.update(task, completed=completed_count, description=f"Processing files... ({file_path.name[:30]}{'...' if len(file_path.name) > 30 else ''})")
                
                # Store results thread-safely
                with results_lock:
                    if error:
                        failed_files.append((str(file_path), error))
                    else:
                        file_key = file_path.name
                        all_results[file_key] = results
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    
    # Create summary report and get output filename
    output_filename = create_batch_summary(all_results, failed_files, output_path, output_json, output_csv)
    
    # Clean final report
    success_count = len(all_results)
    total_count = len(files_to_process)
    
    console.print(f"\n[bold green]Analysis Complete![/bold green]")
    console.print(f"[green]Processed: {success_count}/{total_count} files[/green]")
    console.print(f"[blue]Time: {elapsed_time:.1f}s[/blue]")
    
    if output_filename:
        console.print(f"[cyan]Output: {output_filename}[/cyan]")
    
    if failed_files:
        console.print(f"[red]Failed: {len(failed_files)} files[/red]")
        if verbose:
            console.print("\n[red]Failed files details:[/red]")
            for failed_file, error in failed_files[:10]:  # Show first 10 errors
                console.print(f"[dim]{failed_file}: {error[:100]}{'...' if len(error) > 100 else ''}[/dim]")
            if len(failed_files) > 10:
                console.print(f"[dim]... and {len(failed_files) - 10} more[/dim]")
        else:
            console.print("[dim]Use --verbose to see error details[/dim]")

def create_batch_summary(all_results, failed_files, output_path, output_json, output_csv):
    """Create summary report for batch analysis with custom output behavior"""
    
    from datetime import datetime
    import csv
    
    # Generate timestamp for CSV filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = None
    
    # Handle different output combinations
    if output_csv and not output_json:
        # Case 1: Solo CSV (-c) - Crear un solo CSV con todas las filas
        csv_filename = f"r2inspect_{timestamp}.csv"
        csv_file = output_path / csv_filename
        output_filename = csv_filename
        
        # Crear CSV con todas las filas de archivos procesados
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'name', 'size', 'compile_time', 'file_type', 'md5', 'sha1', 'sha256', 'sha512',
                'imphash', 'ssdeep_hash', 'ssdeep_available', 'tlsh_binary', 'tlsh_text_section',
                'tlsh_available', 'tlsh_functions_with_hash', 'telfhash', 'telfhash_available', 
                'telfhash_symbols_used', 'rich_header_available', 'rich_header_xor_key', 
                'rich_header_checksum', 'richpe_hash', 'rich_header_compilers', 'rich_header_entries',
                'compiler', 'compiler_version', 'compiler_confidence',
                'imports', 'exports', 'sections', 'anti_debug', 'anti_vm', 
                'anti_sandbox', 'yara_matches', 'num_functions', 'num_unique_machoc', 'num_duplicate_functions',
                'num_imports', 'num_exports', 'num_sections'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Escribir una fila por cada archivo
            for file_key, result in all_results.items():
                formatter = OutputFormatter(result)
                csv_data = formatter._extract_csv_data(result)
                writer.writerow(csv_data)
    
    elif output_json and output_csv:
        # Case 2: JSON + CSV (-j -c) - CSV resumen + JSON individual por archivo (ya generado)
        csv_filename = f"r2inspect_{timestamp}.csv"
        csv_file = output_path / csv_filename
        output_filename = f"{csv_filename} + individual JSONs"
        
        # Crear CSV resumen con todas las filas
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'name', 'size', 'compile_time', 'file_type', 'md5', 'sha1', 'sha256', 'sha512',
                'imphash', 'ssdeep_hash', 'ssdeep_available', 'tlsh_binary', 'tlsh_text_section',
                'tlsh_available', 'tlsh_functions_with_hash', 'telfhash', 'telfhash_available', 
                'telfhash_symbols_used', 'rich_header_available', 'rich_header_xor_key', 
                'rich_header_checksum', 'richpe_hash', 'rich_header_compilers', 'rich_header_entries',
                'compiler', 'compiler_version', 'compiler_confidence',
                'imports', 'exports', 'sections', 'anti_debug', 'anti_vm', 
                'anti_sandbox', 'yara_matches', 'num_functions', 'num_unique_machoc', 'num_duplicate_functions',
                'num_imports', 'num_exports', 'num_sections'
            ]
            
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Escribir una fila por cada archivo
            for file_key, result in all_results.items():
                formatter = OutputFormatter(result)
                csv_data = formatter._extract_csv_data(result)
                writer.writerow(csv_data)
    
    elif output_json and not output_csv:
        # Case 3: Solo JSON (-j) - JSON individual por archivo + JSON batch con todos
        # Los archivos individuales ya fueron generados, ahora crear el batch summary
        summary = {
            'batch_summary': {
                'total_files': len(all_results) + len(failed_files),
                'successful_analyses': len(all_results),
                'failed_analyses': len(failed_files),
                'timestamp': datetime.now().isoformat(),
                'processed_files': list(all_results.keys())
            },
            'results': all_results,
            'failed_files': [{'file': f[0], 'error': f[1]} for f in failed_files]
        }
        
        # Agregar estadísticas agregadas
        stats = {
            'packers_detected': [],
            'crypto_patterns': [],
            'suspicious_indicators': [],
            'file_types': {},
            'architectures': {},
            'compilers': {},
        }
        
        for file_key, result in all_results.items():
            # Collect packer information
            if 'packer_info' in result and result['packer_info'].get('detected'):
                stats['packers_detected'].append({
                    'file': file_key,
                    'packer': result['packer_info'].get('name', 'Unknown')
                })
            
            # Collect crypto patterns
            if 'crypto_info' in result and result['crypto_info']:
                for crypto in result['crypto_info']:
                    stats['crypto_patterns'].append({
                        'file': file_key,
                        'pattern': crypto
                    })
            
            # Collect suspicious indicators
            if 'indicators' in result and result['indicators']:
                stats['suspicious_indicators'].extend([
                    {'file': file_key, **indicator} for indicator in result['indicators']
                ])
            
            # File type statistics
            if 'file_info' in result:
                file_type = result['file_info'].get('file_type', 'Unknown')
                stats['file_types'][file_type] = stats['file_types'].get(file_type, 0) + 1
                
                architecture = result['file_info'].get('architecture', 'Unknown')
                stats['architectures'][architecture] = stats['architectures'].get(architecture, 0) + 1
            
            # Compiler statistics
            if 'compiler' in result:
                compiler_info = result['compiler']
                compiler_name = compiler_info.get('compiler', 'Unknown')
                if compiler_info.get('detected', False):
                    stats['compilers'][compiler_name] = stats['compilers'].get(compiler_name, 0) + 1
        
        summary['statistics'] = stats
        
        # Guardar el JSON batch summary
        summary_file = output_path / f"r2inspect_batch_{timestamp}.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, default=str)
        
        output_filename = f"{summary_file.name} + individual JSONs"
    
    # Show summary table
    _show_summary_table(all_results)
    
    return output_filename

def _show_summary_table(all_results):
    """Show a summary table of all analyzed files"""
    from rich.table import Table
    import re
    
    # If more than 10 files, show simplified table with max 10 entries
    if len(all_results) > 10:
        table = Table(title="Analysis Summary")
        table.add_column("Filename", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Compiler", style="magenta")
        table.add_column("Compile Time", style="green")
        
        # Show only first 10 files
        files_shown = 0
        for file_key, result in all_results.items():
            if files_shown >= 10:
                break
                
            try:
                # File info
                file_info = result.get('file_info', {})
                
                # Filename
                filename = file_info.get('name', file_key)
                
                # File type (clean and simplified)
                file_type = file_info.get('file_type', 'Unknown')
                # Clean file type - remove section info and simplify
                file_type = re.sub(r',\s*\d+\s+sections?', '', file_type)
                file_type = re.sub(r'\d+\s+sections?,?\s*', '', file_type)
                file_type = re.sub(r',\s*$', '', file_type.strip())
                
                # Simplify common file types
                if 'PE32+' in file_type:
                    file_type = "PE32+ (x64)"
                elif 'PE32' in file_type:
                    file_type = "PE32 (x86)"
                elif 'ELF' in file_type:
                    file_type = "ELF"
                elif 'Mach-O' in file_type:
                    file_type = "Mach-O"
                
                # Compile time (extract and format)
                compile_time = ''
                if 'pe_info' in result and 'compile_time' in result['pe_info']:
                    compile_time = result['pe_info']['compile_time']
                elif 'elf_info' in result and 'compile_time' in result['elf_info']:
                    compile_time = result['elf_info']['compile_time']
                elif 'macho_info' in result and 'compile_time' in result['macho_info']:
                    compile_time = result['macho_info']['compile_time']
                
                if not compile_time:
                    compile_time = "N/A"
                
                # Compiler information
                compiler_info = result.get('compiler', {})
                compiler_name = 'Unknown'
                if compiler_info.get('detected', False):
                    compiler_name = compiler_info.get('compiler', 'Unknown')
                    version = compiler_info.get('version', '')
                    if version and version != 'Unknown':
                        compiler_name = f"{compiler_name} {version}"
                
                table.add_row(filename, file_type, compiler_name, compile_time)
                files_shown += 1
                
            except Exception as e:
                # If there's an error with any file, show minimal info
                table.add_row(file_key, "Error", "Error", "Error")
                files_shown += 1
        
        # Add a note about remaining files
        if len(all_results) > 10:
            console.print(table)
            console.print(f"[dim]... and {len(all_results) - 10} more files (see CSV output for complete list)[/dim]")
        else:
            console.print(table)
    else:
        # For 10 or fewer files, show detailed table
        table = Table(title="Analysis Summary")
        table.add_column("MD5", style="cyan")
        table.add_column("Type", style="yellow")  
        table.add_column("Compile Time", style="green")
        table.add_column("YARA Matches", style="red")
        
        for file_key, result in all_results.items():
            try:
                # File info
                file_info = result.get('file_info', {})
                
                # MD5 (full hash)
                md5 = file_info.get('md5', 'N/A')
                
                # File type (clean and simplified)
                file_type = file_info.get('file_type', '')
                # Clean file type - remove section info and simplify
                file_type = re.sub(r',\s*\d+\s+sections?', '', file_type)
                file_type = re.sub(r'\d+\s+sections?,?\s*', '', file_type)
                file_type = re.sub(r',\s*$', '', file_type.strip())
                
                # Simplify common file types
                if 'PE32+' in file_type:
                    file_type = "PE32+ (x64)"
                elif 'PE32' in file_type:
                    file_type = "PE32 (x86)"
                elif 'ELF' in file_type:
                    file_type = "ELF"
                elif 'Mach-O' in file_type:
                    file_type = "Mach-O"
                
                # Compile time (extract and format)
                compile_time = ''
                if 'pe_info' in result and 'compile_time' in result['pe_info']:
                    compile_time = result['pe_info']['compile_time']
                elif 'elf_info' in result and 'compile_time' in result['elf_info']:
                    compile_time = result['elf_info']['compile_time']
                elif 'macho_info' in result and 'compile_time' in result['macho_info']:
                    compile_time = result['macho_info']['compile_time']
                
                if not compile_time:
                    compile_time = "N/A"
                
                # YARA matches - show rule names
                yara_matches = []
                if 'yara_matches' in result and isinstance(result['yara_matches'], list):
                    for match in result['yara_matches']:
                        if isinstance(match, dict) and 'rule' in match:
                            yara_matches.append(match['rule'])
                        elif hasattr(match, 'rule'):
                            yara_matches.append(match.rule)
                        else:
                            yara_matches.append(str(match))
                
                yara_str = ", ".join(yara_matches) if yara_matches else "None"
                
                table.add_row(md5, file_type, compile_time, yara_str)
                
            except Exception as e:
                # If there's an error with any file, show minimal info
                table.add_row("Error", "Error", "Error", "Error")
        
        console.print(table)

if __name__ == '__main__':
    main() 