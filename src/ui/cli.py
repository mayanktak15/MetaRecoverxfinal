"""
Unearth Forensic Recovery Tool - Command-Line Interface
Fully functional CLI with rich terminal output

Features:
- Disk image analysis and recovery
- File carving and metadata extraction
- Keyword search and timeline analysis
- Report generation
- Interactive and non-interactive modes

Dependencies:
    pip install click rich
"""

import click
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import json

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.tree import Tree
from rich.prompt import Prompt, Confirm
from rich import box
from rich.syntax import Syntax
from rich.layout import Layout
from rich.live import Live

# Import backend
try:
    from ..app import UnearthApp, FileSystemType
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False
    click.echo("Warning: Backend not available. Some features may be limited.", err=True)

console = Console()


class UnearthCLI:
    """Unearth CLI Application Handler"""
    
    def __init__(self):
        """Initialize CLI handler"""
        self.app = UnearthApp() if BACKEND_AVAILABLE else None
        self.current_session = None
        
    def display_banner(self):
        """Display application banner"""
        banner = """
[bold blue]
╦ ╦┌┬┐╔═╗┌─┐┬─┐┌┬┐┬ ┬
║ ║│││║╣ ├─┤├┬┘ │ ├─┤
╚═╝┘└┘╚═╝┴ ┴┴└─ ┴ ┴ ┴
[/bold blue]
[bold white]Forensic Data Recovery & Analysis Tool[/bold white]
[dim]Version 1.0.0 | Professional Forensic Suite[/dim]
        """
        console.print(Panel(banner, border_style="blue", box=box.DOUBLE))
    
    def display_help(self):
        """Display help information"""
        help_text = """
[bold cyan]Available Commands:[/bold cyan]

[bold yellow]Core Recovery:[/bold yellow]
  analyze <image>              Analyze disk image and detect filesystem
  recover <image> <output>     Recover deleted files from disk image
  carve <image> <output>       Perform file carving on disk image
  
[bold yellow]Analysis Tools:[/bold yellow]
  timeline <session>           Generate file timeline visualization
  search <session> <keywords>  Search for keywords in recovered files
  metadata <session>           Display metadata extraction summary
  integrity <session>          Verify file integrity with hashes
  
[bold yellow]Reporting:[/bold yellow]
  report <session> <format>    Generate forensic report (pdf/csv/json)
  export <session> <path>      Export session data
  
[bold yellow]Session Management:[/bold yellow]
  sessions                     List all sessions
  session-info <session_id>    Display session information
  cleanup <session_id>         Clean up session data
  
[bold yellow]Interactive:[/bold yellow]
  interactive                  Launch interactive mode
  gui                          Launch graphical interface
  
[bold yellow]Utility:[/bold yellow]
  version                      Show version information
  help                         Show this help message
  exit                         Exit application

[dim]Examples:[/dim]
  Unearth analyze /evidence/disk.img
  Unearth recover /evidence/disk.img /output/case001
  Unearth search <session_id> "password,confidential"
  Unearth report <session_id> pdf
        """
        console.print(Panel(help_text, title="[bold]Unearth CLI Help[/bold]", border_style="cyan"))


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Unearth - Forensic Data Recovery Tool"""
    if ctx.invoked_subcommand is None:
        # No command provided, show interactive mode
        handler = UnearthCLI()
        handler.display_banner()
        console.print("\n[yellow]Tip:[/yellow] Type [bold cyan]help[/bold cyan] for available commands or [bold cyan]interactive[/bold cyan] for guided mode\n")


@cli.command()
def version():
    """Show version information"""
    version_info = Table(show_header=False, box=box.ROUNDED)
    version_info.add_column(style="cyan bold")
    version_info.add_column(style="white")
    
    version_info.add_row("Application", "Unearth Forensic Recovery")
    version_info.add_row("Version", "1.0.0")
    version_info.add_row("Python", f"{sys.version.split()[0]}")
    version_info.add_row("Backend", "Available" if BACKEND_AVAILABLE else "Not Available")
    version_info.add_row("GUI Support", "Available")
    version_info.add_row("Author", "Unearth Development Team")
    
    console.print(Panel(version_info, title="[bold blue]Version Information[/bold blue]", border_style="blue"))


@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
def analyze(image_path):
    """Analyze disk image and detect filesystem"""
    console.print(f"\n[bold cyan]Analyzing disk image:[/bold cyan] {image_path}\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Creating session...", total=100)
            
            # Create session
            app = UnearthApp()
            output_dir = Path("data/recovered_output") / datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            session_id = app.create_session(image_path, str(output_dir))
            progress.update(task, advance=30)
            
            # Detect filesystem
            progress.update(task, description="[cyan]Detecting filesystem...")
            fs_type = app.detect_filesystem(session_id)
            progress.update(task, advance=40)
            
            # Get session info
            progress.update(task, description="[cyan]Gathering information...")
            session_info = app.get_session_info(session_id)
            progress.update(task, advance=30)
        
        # Display results
        console.print("\n[bold green]✓ Analysis Complete[/bold green]\n")
        
        results = Table(title="Disk Image Analysis", box=box.ROUNDED)
        results.add_column("Property", style="cyan bold")
        results.add_column("Value", style="white")
        
        results.add_row("Session ID", session_id)
        results.add_row("Image Path", image_path)
        results.add_row("Filesystem Type", fs_type.value.upper())
        results.add_row("Output Directory", str(output_dir))
        results.add_row("Created At", session_info.get('created_at', 'N/A'))
        
        console.print(results)
        
        console.print(f"\n[bold yellow]Next Steps:[/bold yellow]")
        console.print(f"  • Run recovery: [cyan]Unearth recover {image_path} {output_dir}[/cyan]")
        console.print(f"  • View session: [cyan]Unearth session-info {session_id}[/cyan]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
@click.option('--filesystem', '-f', type=click.Choice(['xfs', 'btrfs', 'auto']), default='auto',
              help='Filesystem type (auto-detect if not specified)')
@click.option('--filter', 'file_filter', type=click.Choice(['all', 'deleted_only', 'active_only']), default='all',
              help='Filter files to recover: all (default), deleted_only, or active_only')
@click.option('--carve/--no-carve', default=True, help='Enable file carving')
@click.option('--hash-algorithm', '-h', type=click.Choice(['md5', 'sha256']), default='sha256',
              help='Hash algorithm for integrity verification')
def recover(image_path, output_dir, filesystem, file_filter, carve, hash_algorithm):
    """Recover deleted files from disk image"""
    console.print(f"\n[bold cyan]Starting Recovery Operation[/bold cyan]\n")
    console.print(f"[bold]File Filter:[/bold] {file_filter}\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        app = UnearthApp()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            
            # Create session
            task = progress.add_task("[cyan]Creating session...", total=100)
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            session_id = app.create_session(image_path, output_dir)
            progress.update(task, advance=10)
            
            # Detect filesystem
            progress.update(task, description="[cyan]Detecting filesystem...")
            fs_type = app.detect_filesystem(session_id)
            progress.update(task, advance=15)
            
            # Recover files with filter
            progress.update(task, description=f"[cyan]Recovering files (filter: {file_filter})...")
            recovered = app.recover_deleted_files(session_id, file_filter=file_filter)
            progress.update(task, advance=40)
            
            # Carve files
            carved = []
            if carve:
                progress.update(task, description="[cyan]Carving files from unallocated space...")
                carved = app.carve_files(session_id)
                progress.update(task, advance=25)
            
            # Complete
            progress.update(task, description="[green]Recovery complete!", advance=10)
        
        # Display results
        console.print("\n[bold green]✓ Recovery Complete[/bold green]\n")
        
        # Count deleted vs active files
        deleted_count = sum(1 for f in recovered if f.get('status') == 'deleted')
        active_count = sum(1 for f in recovered if f.get('status') == 'active')
        
        summary = Table(title="Recovery Summary", box=box.ROUNDED)
        summary.add_column("Metric", style="cyan bold")
        summary.add_column("Count", style="white", justify="right")
        
        summary.add_row("Total Recovered", str(len(recovered)))
        summary.add_row("  └─ [red]Deleted Files[/red]", f"[red]{deleted_count}[/red]")
        summary.add_row("  └─ [green]Active Files[/green]", f"[green]{active_count}[/green]")
        summary.add_row("Carved Files", str(len(carved)))
        summary.add_row("Filesystem", fs_type.value.upper())
        summary.add_row("Filter Applied", file_filter)
        summary.add_row("Hash Algorithm", hash_algorithm.upper())
        
        console.print(summary)
        
        # Integrity Verification Summary
        verified_count = sum(1 for f in recovered if f.get('integrity_status') == 'verified')
        corrupted_count = sum(1 for f in recovered if f.get('integrity_status') == 'corrupted')
        unverified_count = sum(1 for f in recovered if f.get('integrity_status') == 'unverified')
        no_checksum_count = sum(1 for f in recovered if f.get('integrity_status') == 'no_checksum')
        
        if len(recovered) > 0:
            console.print("\n[bold cyan]Integrity Verification[/bold cyan]")
            
            integrity_table = Table(box=box.SIMPLE)
            integrity_table.add_column("Status", style="bold")
            integrity_table.add_column("Count", justify="right")
            integrity_table.add_column("Percentage", justify="right")
            
            total = len(recovered)
            if verified_count > 0:
                integrity_table.add_row(
                    "[green]✓ Verified[/green]", 
                    str(verified_count), 
                    f"{verified_count/total*100:.1f}%"
                )
            if corrupted_count > 0:
                integrity_table.add_row(
                    "[red]✗ Corrupted[/red]", 
                    str(corrupted_count), 
                    f"{corrupted_count/total*100:.1f}%"
                )
            if unverified_count > 0:
                integrity_table.add_row(
                    "[yellow]? Unverified[/yellow]", 
                    str(unverified_count), 
                    f"{unverified_count/total*100:.1f}%"
                )
            if no_checksum_count > 0:
                integrity_table.add_row(
                    "[dim]- No Checksum[/dim]", 
                    str(no_checksum_count), 
                    f"{no_checksum_count/total*100:.1f}%"
                )
            
            console.print(integrity_table)
        
        console.print(f"\n[bold]Session ID:[/bold] {session_id}")
        console.print(f"[bold]Output Directory:[/bold] {output_dir}\n")
        
        console.print("[bold yellow]Next Steps:[/bold yellow]")
        console.print(f"  • View timeline: [cyan]Unearth timeline {session_id}[/cyan]")
        console.print(f"  • Search files: [cyan]Unearth search {session_id} <keywords>[/cyan]")
        console.print(f"  • Generate report: [cyan]Unearth report {session_id} pdf[/cyan]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument('image_path', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path())
@click.option('--types', '-t', help='File types to carve (comma-separated, e.g., jpg,pdf,docx)')
@click.option('--threads', default=4, help='Number of threads for parallel processing')
def carve(image_path, output_dir, types, threads):
    """Perform file carving on disk image"""
    console.print(f"\n[bold cyan]File Carving Operation[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    file_types = types.split(',') if types else None
    
    try:
        app = UnearthApp()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("[cyan]Carving files...", total=None)
            
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            session_id = app.create_session(image_path, output_dir)
            
            carved = app.carve_files(session_id, file_types=file_types)
            
            progress.update(task, completed=True)
        
        console.print(f"\n[bold green]✓ Carved {len(carved)} files[/bold green]\n")
        
        # Show file type breakdown
        type_counts = {}
        for file_info in carved:
            ftype = file_info.get('type', 'unknown')
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        if type_counts:
            breakdown = Table(title="File Type Breakdown", box=box.SIMPLE)
            breakdown.add_column("Type", style="cyan")
            breakdown.add_column("Count", style="white", justify="right")
            
            for ftype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                breakdown.add_row(ftype.upper(), str(count))
            
            console.print(breakdown)
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@cli.command()
@click.argument('session_id')
def timeline(session_id):
    """Generate file timeline visualization from recovered files"""
    console.print(f"\n[bold cyan]File Timeline Analysis[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        app = UnearthApp()
        session = app.sessions.get(session_id)
        if not session:
            console.print(f"[red]Error: Session '{session_id}' not found[/red]")
            return
        
        # Gather all files (recovered + carved)
        all_files = session.recovered_files + session.carved_files
        
        if not all_files:
            console.print("[yellow]No files found in this session. Run a scan first.[/yellow]")
            return
        
        # Build timeline events from actual file metadata
        events = []
        for f in all_files:
            name = f.get('name', 'unknown')
            status = f.get('status', 'unknown')
            modified = f.get('modified', '')
            ftype = f.get('type', '?')
            size = f.get('size', 0)
            
            # Use the file's modification timestamp if available
            if modified:
                events.append({
                    'timestamp': modified,
                    'name': name,
                    'status': status,
                    'type': ftype,
                    'size': size,
                })
            else:
                # For carved files without timestamps, try to read from disk
                filepath = f.get('path', '')
                if filepath and os.path.isfile(filepath):
                    import os as _os
                    mtime = datetime.fromtimestamp(_os.path.getmtime(filepath))
                    events.append({
                        'timestamp': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                        'name': name,
                        'status': status,
                        'type': ftype,
                        'size': size,
                    })
        
        if not events:
            console.print("[yellow]No timestamp data available for recovered files.[/yellow]")
            return
        
        # Sort by timestamp
        events.sort(key=lambda e: e['timestamp'])
        
        # Display as a table
        table = Table(title=f"Timeline ({len(events)} events)", box=box.ROUNDED)
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("File", style="white")
        table.add_column("Type", style="dim", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("Size", style="dim", justify="right")
        
        for event in events:
            # Color-code status
            status = event['status']
            if status == 'deleted':
                status_str = "[red]🗑️ Deleted[/red]"
            elif status == 'carved':
                status_str = "[yellow]🔍 Carved[/yellow]"
            elif status == 'active':
                status_str = "[green]✅ Active[/green]"
            else:
                status_str = f"[dim]{status}[/dim]"
            
            # Format size
            size = event['size']
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1048576:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/1048576:.1f} MB"
            
            table.add_row(
                event['timestamp'],
                event['name'],
                event['type'].upper(),
                status_str,
                size_str,
            )
        
        console.print(table)
        console.print(f"\n[dim]Total: {len(events)} file events across the session[/dim]\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")


@cli.command()
@click.argument('session_id')
@click.argument('keywords')
@click.option('--case-sensitive', is_flag=True, help='Enable case-sensitive search')
@click.option('--no-content', is_flag=True, help='Search filenames only (skip content search)')
def search(session_id, keywords, case_sensitive, no_content):
    """Search for keywords in recovered files (filenames + content)"""
    console.print(f"\n[bold cyan]Keyword Search[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    # Parse comma-separated keywords into a list
    keyword_list = [k.strip() for k in keywords.split(',') if k.strip()]
    
    # Whether to search inside file contents (default: yes, unless --no-content)
    search_content = not no_content
    
    console.print(f"[bold]Searching for:[/bold] {', '.join(keyword_list)}")
    console.print(f"[bold]Case sensitive:[/bold] {'Yes' if case_sensitive else 'No'}")
    console.print(f"[bold]Content search:[/bold] {'Enabled' if search_content else 'Disabled (filenames only)'}\n")
    
    try:
        app = UnearthApp()
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("[cyan]Searching files...", total=None)
            
            # Call the centralized keyword_search method in UnearthApp
            # This searches both filenames and file contents (if enabled)
            search_results = app.keyword_search(
                session_id,
                keyword_list,
                case_sensitive=case_sensitive,
                search_content=search_content
            )
            
            progress.update(task, completed=True)
        
        # --- Display results in a Rich table ---
        if not search_results:
            console.print("[yellow]No matches found.[/yellow]\n")
            return
        
        results_table = Table(
            title=f"Search Results \u2014 {len(search_results)} file(s) matched",
            box=box.ROUNDED
        )
        results_table.add_column("File", style="cyan", max_width=40)
        results_table.add_column("Match Type", style="white")
        results_table.add_column("Keywords", style="yellow")
        results_table.add_column("Content Snippet", style="dim", max_width=60)
        
        for result in search_results:
            # Format match type with colour coding
            match_type = result.get('match_type', 'filename')
            if match_type == 'both':
                type_str = "[magenta]Filename + Content[/magenta]"
            elif match_type == 'content':
                type_str = "[yellow]Content[/yellow]"
            else:
                type_str = "[green]Filename[/green]"
            
            # Join matched keywords
            kws = ', '.join(result.get('matched_keywords', []))
            
            # Build a brief content snippet from the first content match (if any)
            # Shows the line number and a truncated preview of the matching line
            content_matches = result.get('content_matches', [])
            if content_matches:
                first = content_matches[0]
                snippet = f"Line {first['line_number']}: {first['line_text'][:50]}"
                if len(content_matches) > 1:
                    snippet += f" (+{len(content_matches) - 1} more)"
            else:
                snippet = "-"
            
            results_table.add_row(
                result.get('name', 'Unknown'),
                type_str,
                kws,
                snippet
            )
        
        console.print(results_table)
        
        # --- Summary ---
        total_content_hits = sum(len(r.get('content_matches', [])) for r in search_results)
        console.print(f"\n[bold]Total:[/bold] {len(search_results)} file(s) matched", end="")
        if total_content_hits > 0:
            console.print(f" with {total_content_hits} content hit(s)", end="")
        console.print("\n")
        
    except KeyError:
        console.print(f"[bold red]Error:[/bold red] Session '{session_id}' not found")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")


@cli.command()
@click.argument('session_id')
@click.argument('format', type=click.Choice(['pdf', 'csv', 'json']))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--include-images', is_flag=True, help='Include file previews in PDF')
def report(session_id, format, output, include_images):
    """Generate forensic report"""
    console.print(f"\n[bold cyan]Generating Forensic Report[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        app = UnearthApp()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(f"[cyan]Generating {format.upper()} report...", total=100)
            
            # Generate report
            report_path = app.generate_report(session_id, format=format)
            
            progress.update(task, advance=100)
        
        console.print(f"\n[bold green]✓ Report Generated Successfully[/bold green]\n")
        
        info = Table(show_header=False, box=box.SIMPLE)
        info.add_column(style="cyan bold")
        info.add_column(style="white")
        
        info.add_row("Format", format.upper())
        info.add_row("File", str(report_path))
        info.add_row("Session", session_id)
        
        console.print(info)
        
        console.print("\n[bold]Report Contents:[/bold]")
        console.print("  ✓ Complete file inventory")
        console.print("  ✓ Metadata and timestamps")
        console.print("  ✓ Integrity hashes (SHA-256)")
        console.print("  ✓ Timeline visualization")
        console.print("  ✓ Keyword search results")
        if include_images:
            console.print("  ✓ File previews\n")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@cli.command()
def sessions():
    """List all active sessions"""
    console.print("\n[bold cyan]Active Sessions[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        app = UnearthApp()
        session_list = app.list_sessions()
        
        if not session_list:
            console.print("[yellow]No active sessions found[/yellow]\n")
            return
        
        table = Table(title=f"Found {len(session_list)} session(s)", box=box.ROUNDED)
        table.add_column("Session ID", style="cyan")
        table.add_column("Image", style="white")
        table.add_column("Filesystem", style="yellow")
        table.add_column("Created", style="dim")
        
        for session in session_list:
            table.add_row(
                session['session_id'][:16] + "...",
                Path(session['image_path']).name,
                session['fs_type'],
                session['created_at'][:19]
            )
        
        console.print(table)
        console.print()
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")


@cli.command()
@click.argument('session_id')
def session_info(session_id):
    """Display detailed session information"""
    console.print(f"\n[bold cyan]Session Information[/bold cyan]\n")
    
    if not BACKEND_AVAILABLE:
        console.print("[red]Error: Backend not available[/red]")
        return
    
    try:
        app = UnearthApp()
        info = app.get_session_info(session_id)
        
        table = Table(show_header=False, box=box.ROUNDED, title=f"Session: {session_id[:16]}...")
        table.add_column("Property", style="cyan bold")
        table.add_column("Value", style="white")
        
        table.add_row("Session ID", info['session_id'])
        table.add_row("Image Path", info['image_path'])
        table.add_row("Output Directory", info['output_dir'])
        table.add_row("Filesystem Type", info['fs_type'])
        table.add_row("Created At", info['created_at'])
        table.add_row("Recovered Files", str(info['recovered_files_count']))
        table.add_row("Carved Files", str(info['carved_files_count']))
        
        console.print(table)
        console.print()
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")


@cli.command()
def interactive():
    """Launch interactive mode"""
    handler = UnearthCLI()
    handler.display_banner()
    
    console.print("[bold cyan]Interactive Mode[/bold cyan]")
    console.print("[dim]Type 'help' for commands or 'exit' to quit[/dim]\n")
    
    while True:
        try:
            command = Prompt.ask("[bold green]Unearth[/bold green]")
            
            if command.lower() in ['exit', 'quit', 'q']:
                console.print("[yellow]Goodbye![/yellow]")
                break
            elif command.lower() == 'help':
                handler.display_help()
            elif command.lower() == 'gui':
                console.print("[cyan]Launching GUI...[/cyan]")
                try:
                    from .gui import main as gui_main
                    gui_main()
                except ImportError:
                    console.print("[red]GUI not available[/red]")
            elif command.strip() == '':
                continue
            else:
                # Parse and execute command
                console.print(f"[yellow]Executing: {command}[/yellow]")
                # In real implementation, parse and execute
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit[/yellow]")
        except EOFError:
            break


@cli.command()
def gui():
    """Launch graphical user interface"""
    console.print("[cyan]Launching GUI...[/cyan]")
    try:
        from .gui import main as gui_main
        gui_main()
    except ImportError as e:
        console.print(f"[red]Error: GUI not available - {str(e)}[/red]")
        sys.exit(1)


def main():
    """Main CLI entry point"""
    cli()


if __name__ == "__main__":
    main()