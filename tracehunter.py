import argparse
import datetime
import os
import platform
import socket
import sys
from typing import Any, Dict, Optional

import sys; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); from core import __author__, __repository__, __version__
from core.forensic_exporter import ForensicExporter
from core.i18n import get_text
from core.network_correlator import NetworkCorrelator
from core.persistence_engine import PersistenceEngine
from core.process_engine import ProcessEngine
from core.yara_scanner import YaraScanner

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    Console = None  # type: ignore


def build_arg_parser(lang: str = "en") -> argparse.ArgumentParser:
    """Build command-line argument parser with bilingual help descriptions."""
    parser = argparse.ArgumentParser(
        prog="tracehunter.py",
        description=get_text(lang, "cli_desc"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scan-all",
        action="store_true",
        help=get_text(lang, "arg_scan_all"),
    )
    parser.add_argument(
        "--hunt-processes",
        action="store_true",
        help=get_text(lang, "arg_hunt_proc"),
    )
    parser.add_argument(
        "--hunt-persistence",
        action="store_true",
        help=get_text(lang, "arg_hunt_pers"),
    )
    parser.add_argument(
        "--audit-network",
        action="store_true",
        help=get_text(lang, "arg_audit_net"),
    )
    parser.add_argument(
        "--yara",
        metavar="DIR",
        type=str,
        default=None,
        help=get_text(lang, "arg_yara"),
    )
    parser.add_argument(
        "--output-format",
        choices=["table", "json", "stix"],
        default="table",
        help=get_text(lang, "arg_out_fmt"),
    )
    parser.add_argument(
        "--output-file",
        metavar="FILE",
        type=str,
        default=None,
        help=get_text(lang, "arg_out_file"),
    )
    parser.add_argument(
        "--lang",
        choices=["en", "id"],
        default="en",
        help=get_text(lang, "arg_lang"),
    )
    return parser


def format_severity_badge(severity: str) -> Any:
    """Return calm, readable severity badge for Rich tables."""
    if Console is None:
        return severity
    upper = severity.upper()
    if upper in ("HIGH", "TINGGI"):
        return Text(severity, style="bold red")
    if upper in ("MEDIUM", "SEDANG"):
        return Text(severity, style="yellow")
    if upper in ("LOW", "RENDAH"):
        return Text(severity, style="cyan")
    return Text(severity, style="dim")


def render_table_output(audit_results: Dict[str, Any], lang: str) -> None:
    """Render structured, neutral console tables using the `rich` library."""
    if Console is None:
        # Fallback plain-text tabular summary if `rich` is not installed
        print(f"=== {get_text(lang, 'app_title')} (v{__version__}) ===")
        for mod_name, mod_data in audit_results.items():
            print(f"\n[{mod_name}] {get_text(lang, 'msg_total_scanned')}: {mod_data.get('total_inspected', 0)} | {get_text(lang, 'msg_anomalies_found')}: {mod_data.get('anomalies_count', 0)}")
            for finding in mod_data.get("findings", []):
                print(f"  - {finding}")
        return

    console = Console()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Header Panel (Neutral, concise, no ASCII art)
    header_text = Text()
    header_text.append(f"{get_text(lang, 'app_title')} ", style="bold white")
    header_text.append(f"v{__version__}\n", style="dim")
    header_text.append(f"{get_text(lang, 'app_subtitle')}\n", style="steel_blue1")
    header_text.append(f"Repository: {__repository__} | Maintainer: {__author__}", style="dim")
    console.print(Panel(header_text, box=box.SQUARE, border_style="slate_blue3", expand=False))

    # Host Metadata Summary Table
    meta_table = Table(
        title=get_text(lang, "status_sysinfo"),
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white",
    )
    meta_table.add_column(get_text(lang, "col_field"), style="dim", width=24)
    meta_table.add_column(get_text(lang, "col_value"), style="white")
    meta_table.add_row("Hostname", socket.gethostname())
    meta_table.add_row("Operating System", f"{platform.system()} {platform.release()} ({platform.machine()})")
    meta_table.add_row("Python Runtime", platform.python_version())
    meta_table.add_row("Timestamp (UTC)", now_str)
    console.print(meta_table)
    console.print()

    # 1. Process Engine Results
    if "process_engine" in audit_results:
        proc_data = audit_results["process_engine"]
        proc_table = Table(
            title=f"{get_text(lang, 'sec_process')} [{get_text(lang, 'msg_total_scanned')}: {proc_data['total_inspected']} | {get_text(lang, 'msg_anomalies_found')}: {proc_data['anomalies_count']}]",
            box=box.SIMPLE_HEAVY,
            header_style="bold white",
            expand=True,
        )
        proc_table.add_column(get_text(lang, "col_pid"), justify="right", width=7)
        proc_table.add_column(get_text(lang, "col_ppid"), justify="right", width=7)
        proc_table.add_column(get_text(lang, "col_proc_name"), width=18)
        proc_table.add_column(get_text(lang, "col_parent_name"), width=16)
        proc_table.add_column(get_text(lang, "col_mitre"), width=10)
        proc_table.add_column(get_text(lang, "col_severity"), width=10)
        proc_table.add_column(get_text(lang, "col_sha256"), width=18)
        proc_table.add_column(get_text(lang, "col_details"), ratio=1)

        findings = proc_data.get("findings", [])
        if findings:
            for item in findings:
                sha_short = item["sha256"][:16] + "..." if len(item.get("sha256", "")) == 64 else item.get("sha256", "N/A")
                proc_table.add_row(
                    str(item["pid"]),
                    str(item["ppid"]),
                    str(item["process_name"]),
                    str(item["parent_name"]),
                    str(item["mitre_id"]),
                    format_severity_badge(str(item["severity"])),
                    sha_short,
                    str(item["description"]),
                )
        else:
            # Show sample of verified active processes when zero anomalies are detected
            for item in proc_data.get("inventory_sample", [])[:8]:
                sha_short = item["sha256"][:16] + "..." if len(item.get("sha256", "")) == 64 else item.get("sha256", "N/A")
                proc_table.add_row(
                    str(item["pid"]),
                    str(item["ppid"]),
                    str(item["process_name"]),
                    str(item["parent_name"]),
                    "-",
                    format_severity_badge(get_text(lang, "sev_info")),
                    sha_short,
                    str(item["exe_path"]),
                )
        console.print(proc_table)
        if not findings:
            console.print(f"  [dim]{get_text(lang, 'msg_no_anomalies')}[/dim]\n")
        else:
            console.print()

    # 2. Persistence Engine Results
    if "persistence_engine" in audit_results:
        pers_data = audit_results["persistence_engine"]
        pers_table = Table(
            title=f"{get_text(lang, 'sec_persistence')} [{get_text(lang, 'msg_total_scanned')}: {pers_data['total_inspected']} | {get_text(lang, 'msg_anomalies_found')}: {pers_data['anomalies_count']}]",
            box=box.SIMPLE_HEAVY,
            header_style="bold white",
            expand=True,
        )
        pers_table.add_column(get_text(lang, "col_pers_type"), width=20)
        pers_table.add_column(get_text(lang, "col_pers_name"), width=22)
        pers_table.add_column(get_text(lang, "col_mitre"), width=10)
        pers_table.add_column(get_text(lang, "col_severity"), width=10)
        pers_table.add_column(get_text(lang, "col_pers_target"), ratio=1)
        pers_table.add_column(get_text(lang, "col_details"), ratio=1)

        findings = pers_data.get("findings", [])
        for item in findings:
            pers_table.add_row(
                str(item["mechanism"]),
                str(item["entry_name"]),
                str(item["mitre_id"]),
                format_severity_badge(str(item["severity"])),
                str(item["target"]),
                str(item["description"]),
            )
        console.print(pers_table)
        if not findings:
            console.print(f"  [dim]{get_text(lang, 'msg_no_anomalies')}[/dim]\n")
        else:
            console.print()

    # 3. Network Correlator Results
    if "network_correlator" in audit_results:
        net_data = audit_results["network_correlator"]
        net_table = Table(
            title=f"{get_text(lang, 'sec_network')} [{get_text(lang, 'msg_total_scanned')}: {net_data['total_inspected']} | {get_text(lang, 'msg_anomalies_found')}: {net_data['anomalies_count']}]",
            box=box.SIMPLE_HEAVY,
            header_style="bold white",
            expand=True,
        )
        net_table.add_column(get_text(lang, "col_pid"), justify="right", width=7)
        net_table.add_column(get_text(lang, "col_proc_name"), width=18)
        net_table.add_column(get_text(lang, "col_proto"), width=6)
        net_table.add_column(get_text(lang, "col_laddr"), width=22)
        net_table.add_column(get_text(lang, "col_raddr"), width=22)
        net_table.add_column(get_text(lang, "col_state"), width=13)
        net_table.add_column(get_text(lang, "col_scope"), width=20)
        net_table.add_column(get_text(lang, "col_severity"), width=10)

        rows_to_show = net_data.get("findings") or net_data.get("all_sockets", [])[:15]
        for item in rows_to_show:
            net_table.add_row(
                str(item["pid"]),
                str(item["process_name"]),
                str(item["protocol"]),
                str(item["local_address"]),
                str(item["remote_address"]),
                str(item["state"]),
                str(item["scope"]),
                format_severity_badge(str(item["severity"])),
            )
        console.print(net_table)
        if not net_data.get("findings"):
            console.print(f"  [dim]{get_text(lang, 'msg_no_anomalies')}[/dim]\n")
        else:
            console.print()

    # 4. YARA Scanner Results
    if "yara_scanner" in audit_results:
        yara_data = audit_results["yara_scanner"]
        yara_table = Table(
            title=f"{get_text(lang, 'sec_yara')} [{get_text(lang, 'msg_total_scanned')}: {yara_data['total_inspected']} | {get_text(lang, 'msg_anomalies_found')}: {yara_data['anomalies_count']}]",
            box=box.SIMPLE_HEAVY,
            header_style="bold white",
            expand=True,
        )
        yara_table.add_column(get_text(lang, "col_rule"), width=28)
        yara_table.add_column(get_text(lang, "col_mitre"), width=10)
        yara_table.add_column(get_text(lang, "col_severity"), width=10)
        yara_table.add_column(get_text(lang, "col_sha256"), width=18)
        yara_table.add_column(get_text(lang, "col_file"), ratio=1)
        yara_table.add_column(get_text(lang, "col_strings"), ratio=1)

        findings = yara_data.get("findings", [])
        for item in findings:
            sha_short = item["sha256"][:16] + "..." if len(item.get("sha256", "")) == 64 else item.get("sha256", "N/A")
            yara_table.add_row(
                str(item["rule_name"]),
                str(item["mitre_id"]),
                format_severity_badge(str(item["severity"])),
                sha_short,
                str(item["file_path"]),
                str(item["matched_strings"]),
            )
        console.print(yara_table)
        if not findings:
            console.print(f"  [dim]{get_text(lang, 'msg_no_anomalies')}[/dim]\n")
        else:
            console.print()

    console.print(f"[dim]{get_text(lang, 'msg_audit_complete')}[/dim]")


def execute_selected_audits(
    scan_all: bool,
    hunt_processes: bool,
    hunt_persistence: bool,
    audit_network: bool,
    yara_target: Optional[str],
    lang: str,
) -> Dict[str, Any]:
    """Run requested forensic engines and return aggregated dictionary."""
    results: Dict[str, Any] = {}
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")

    if scan_all or hunt_processes:
        proc_engine = ProcessEngine(lang=lang)
        results["process_engine"] = proc_engine.run_audit()

    if scan_all or hunt_persistence:
        pers_engine = PersistenceEngine(lang=lang)
        results["persistence_engine"] = pers_engine.run_audit()

    if scan_all or audit_network:
        net_engine = NetworkCorrelator(lang=lang)
        results["network_correlator"] = net_engine.run_audit()

    if scan_all or yara_target is not None:
        yara_engine = YaraScanner(rules_dir=rules_dir, lang=lang)
        results["yara_scanner"] = yara_engine.run_audit(target_dir=yara_target)

    return results


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for TraceHunter CLI."""
    raw_args = argv if argv is not None else sys.argv[1:]

    # Pre-detect `--lang` so `--help` renders in the requested language
    detected_lang = "en"
    for idx, arg in enumerate(raw_args):
        if arg == "--lang" and idx + 1 < len(raw_args):
            detected_lang = raw_args[idx + 1].lower()
        elif arg.startswith("--lang="):
            detected_lang = arg.split("=", 1)[1].lower()

    parser = build_arg_parser(lang=detected_lang)
    args = parser.parse_args(raw_args)
    lang = args.lang

    # Default to `--scan-all` if no specific module flag was provided
    if not (args.scan_all or args.hunt_processes or args.hunt_persistence or args.audit_network or args.yara is not None):
        args.scan_all = True

    audit_results = execute_selected_audits(
        scan_all=args.scan_all,
        hunt_processes=args.hunt_processes,
        hunt_persistence=args.hunt_persistence,
        audit_network=args.audit_network,
        yara_target=args.yara,
        lang=lang,
    )

    exporter = ForensicExporter()

    if args.output_format == "json":
        out_file = args.output_file or "tracehunter_report.json"
        json_payload = exporter.export_json(audit_results, output_path=out_file)
        print(json_payload)
        print(f"\n[+] {get_text(lang, 'msg_export_json')}: {os.path.abspath(out_file)}", file=sys.stderr)
    elif args.output_format == "stix":
        out_file = args.output_file or "tracehunter_stix_bundle.json"
        stix_payload = exporter.export_stix(audit_results, output_path=out_file)
        print(stix_payload)
        print(f"\n[+] {get_text(lang, 'msg_export_stix')}: {os.path.abspath(out_file)}", file=sys.stderr)
    else:
        render_table_output(audit_results, lang=lang)
        if args.output_file:
            exporter.export_json(audit_results, output_path=args.output_file)
            print(f"[+] {get_text(lang, 'msg_export_json')}: {os.path.abspath(args.output_file)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
