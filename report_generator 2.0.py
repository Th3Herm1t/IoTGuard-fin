import os
import re
import json
import hashlib
import datetime
from typing import Dict, Any, List
from collections import Counter
import subprocess

# Utility Functions

def calculate_hash(file_path: str) -> str:
    """Calculates SHA256 hash of the file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating SHA256 hash for {file_path}: {e}")
        return ""

def initialize_json_structure(sample_name: str, elf_file_path: str) -> Dict[str, Any]:
    """Initialize the JSON structure for a given sample."""
    file_stat = os.stat(elf_file_path)
    
    json_structure = {
        "sample_id": hashlib.sha256(sample_name.encode()).hexdigest(),
        "file_metadata": {
            "file_name": os.path.basename(elf_file_path),
            "file_size": file_stat.st_size,
            "sha256_hash": calculate_hash(elf_file_path),
            "permissions": oct(file_stat.st_mode),
            "creation_time": datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "last_modified_time": datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat()
        },
        "strace_analysis": {},  # Placeholder for strace analysis
        "static_analysis": {},  # Placeholder for static analysis
        "ltrace_analysis": {},  # Placeholder for ltrace analysis
        "network_analysis": {},  # Placeholder for network analysis
        "system_info_before": {},  # Placeholder for system info before
        "system_info_after": {},  # Placeholder for system info after
        "analysis_time": 0  # Placeholder for analysis time
    }
    
    return json_structure

def save_json(json_data: Dict[str, Any], output_path: str):
    """Saves the JSON structure to a file."""
    with open(output_path, 'w') as json_file:
        json.dump(json_data, json_file, indent=4)
    print(f"JSON saved to {output_path}")

# Static Analysis Parsing Functions

def parse_elf_header(analysis_data: str) -> Dict[str, Any]:
    """Parse the ELF header from the analysis log."""
    elf_header = {}
    header_pattern = re.compile(r"^\s*(.*):\s+(.*)$")
    
    for line in analysis_data.splitlines():
        match = header_pattern.match(line)
        if match:
            key = match.group(1).strip().replace(' ', '_').lower()
            value = match.group(2).strip()
            elf_header[key] = value
    
    return elf_header

def parse_section_headers(analysis_data: str) -> List[Dict[str, Any]]:
    """Parse the section headers from the analysis log."""
    sections = []
    section_header_pattern = re.compile(r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
    
    for line in analysis_data.splitlines():
        match = section_header_pattern.match(line)
        if match:
            section = {
                "index": int(match.group(1)),
                "name": match.group(2),
                "type": match.group(3),
                "address": match.group(4),
                "offset": match.group(5),
                "size": match.group(6),
                "flags": match.group(7)
            }
            sections.append(section)
    
    return sections

def parse_program_headers(analysis_data: str) -> List[Dict[str, Any]]:
    """Parse the program headers from the analysis log."""
    program_headers = []
    program_header_pattern = re.compile(r"^\s*(\S+)\s+(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(0x\S+)\s+(.*)$")
    
    for line in analysis_data.splitlines():
        match = program_header_pattern.match(line)
        if match:
            header = {
                "type": match.group(1),
                "offset": match.group(2),
                "virt_addr": match.group(3),
                "phys_addr": match.group(4),
                "file_size": match.group(5),
                "mem_size": match.group(6),
                "flags": match.group(7)
            }
            program_headers.append(header)
    
    return program_headers

def parse_symbol_table(analysis_data: str) -> List[Dict[str, Any]]:
    """Parse the symbol table from the analysis log."""
    symbols = []
    symbol_pattern = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")
    
    for line in analysis_data.splitlines():
        match = symbol_pattern.match(line)
        if match:
            symbol = {
                "index": int(match.group(1)),
                "value": match.group(2),
                "size": int(match.group(3)),
                "type": match.group(4),
                "bind": match.group(5),
                "visibility": match.group(6),
                "section_index": match.group(7),
                "name": match.group(8)
            }
            symbols.append(symbol)
    
    return symbols

def summarize_static_analysis(static_data: Dict[str, Any]) -> Dict[str, Any]:
    """Summarizes the static analysis data to extract key features."""
    summary = {}
    
    # Summarize Section Headers
    section_types = [section['type'] for section in static_data['sections']]
    section_sizes = [int(section['size'], 16) for section in static_data['sections']]
    
    summary['section_type_count'] = dict(Counter(section_types))
    summary['total_section_size'] = sum(section_sizes)
    summary['max_section_size'] = max(section_sizes)
    summary['min_section_size'] = min(section_sizes)
    summary['avg_section_size'] = sum(section_sizes) / len(section_sizes) if section_sizes else 0
    
    # Summarize Program Headers
    program_types = [header['type'] for header in static_data['program_headers']]
    summary['program_type_count'] = dict(Counter(program_types))
    
    # Summarize Symbols
    symbol_types = [symbol['type'] for symbol in static_data['symbols']]
    summary['symbol_type_count'] = dict(Counter(symbol_types))
    summary['total_symbols'] = len(static_data['symbols'])
    
    return summary

def parse_static_analysis(static_log_path: str) -> Dict[str, Any]:
    """Parse and summarize the static analysis log."""
    with open(static_log_path, 'r') as log_file:
        analysis_data = log_file.read()
    
    # Parsing different sections of the static analysis
    elf_header = parse_elf_header(analysis_data)
    sections = parse_section_headers(analysis_data)
    program_headers = parse_program_headers(analysis_data)
    symbols = parse_symbol_table(analysis_data)
    
    # Summarize the static analysis data
    raw_static_data = {
        "elf_header": elf_header,
        "sections": sections,
        "program_headers": program_headers,
        "symbols": symbols
    }
    
    return summarize_static_analysis(raw_static_data)

# Strace Parsing Functions

def parse_strace_output(strace_data: str) -> Dict[str, Any]:
    """Parse strace output and extract syscall information."""
    syscalls = []
    syscall_pattern = re.compile(
        r"^(?P<pid>\d+)\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$"
    )

    for line in strace_data.splitlines():
        match = syscall_pattern.match(line)
        if match:
            syscall_info = {
                "pid": int(match.group("pid")),
                "syscall": match.group("syscall"),
                "args": match.group("args"),
                "result": match.group("result")
            }
            syscalls.append(syscall_info)
        elif "SIG" in line:
            # Capture signals separately
            syscalls.append({"signal": line.strip()})

    return {"syscalls": syscalls}

def summarize_strace_data(parsed_strace: Dict[str, Any]) -> Dict[str, Any]:
    """Summarizes the strace data to extract key features."""
    summary = {
        "total_syscalls": 0,
        "syscall_counts": {},
        "errors": [],
        "signals": []
    }
    
    for entry in parsed_strace["syscalls"]:
        if "syscall" in entry:
            syscall = entry["syscall"]
            summary["total_syscalls"] += 1
            if syscall not in summary["syscall_counts"]:
                summary["syscall_counts"][syscall] = 0
            summary["syscall_counts"][syscall] += 1
            
            # Check for errors
            if entry["result"].startswith("-1"):
                summary["errors"].append(entry)
                
        elif "signal" in entry:
            summary["signals"].append(entry["signal"])
    
    return summary

# Ltrace Parsing Functions

def parse_ltrace_output(ltrace_data: str) -> Dict[str, Any]:
    """Parse ltrace output and extract trace information."""
    traces = []
    trace_pattern = re.compile(
        r"^(?P<function>\S+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$"
    )

    for line in ltrace_data.splitlines():
        match = trace_pattern.match(line)
        if match:
            trace_info = {
                "function": match.group("function"),
                "args": match.group("args"),
                "result": match.group("result")
            }
            traces.append(trace_info)
    
    return {"traces": traces}

def summarize_ltrace_data(parsed_ltrace: Dict[str, Any]) -> Dict[str, Any]:
    """Summarizes the ltrace data to extract key features."""
    summary = {
        "total_traces": len(parsed_ltrace["traces"]),
        "function_calls": Counter(trace["function"] for trace in parsed_ltrace["traces"]),
        "results": Counter(trace["result"] for trace in parsed_ltrace["traces"])
    }
    
    return summary

# Network Analysis Functions

def analyze_network_traffic(pcap_file_path: str) -> Dict[str, Any]:
    """Analyze network traffic using tshark and summarize results."""
    network_analysis = {}
    
    try:
        # Run tshark command
        result = subprocess.run(
            ["tshark", "-r", pcap_file_path, "-q", "-z", "io,stat,0"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        # Parse tshark output
        network_analysis['io_statistics'] = output
        
        # More detailed analysis can be added here
        
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        network_analysis['error'] = str(e)
    
    return network_analysis

# Main Integration Function

def integrate_and_save(config: Dict[str, Any]):
    """Integrates parsed data into JSON structure and saves it."""
    
    # Extract relevant paths from the configuration
    sample_name = config['sample_name']
    elf_file_path = os.path.join(config['malware_dir'], f"{sample_name}/{sample_name}.elf")
    static_log_path = os.path.join(config['malware_dir'], f"{sample_name}/{sample_name}_static_analysis.log")
    strace_log_path = os.path.join(config['malware_dir'], f"{sample_name}/{sample_name}_strace.log")
    ltrace_log_path = os.path.join(config['malware_dir'], f"{sample_name}/ltrace_output.txt")
    pcap_file_path = os.path.join(config['malware_dir'], f"{sample_name}/{sample_name}_tshark.pcap")
    output_json_path = os.path.join(config['output_dir'], f"{sample_name}_analysis.json")

    # Initialize JSON structure
    json_data = initialize_json_structure(sample_name, elf_file_path)

    # Populate with parsed static analysis data
    if config.get('process_static_analysis', True):
        json_data['static_analysis'] = parse_static_analysis(static_log_path)
    
    # Populate with parsed strace analysis data
    if config.get('process_strace', True):
        with open(strace_log_path, 'r') as strace_file:
            strace_data = strace_file.read()
            parsed_strace = parse_strace_output(strace_data)
            json_data['strace_analysis'] = summarize_strace_data(parsed_strace)
    
    # Populate with parsed ltrace analysis data
    if config.get('process_ltrace', True):
        with open(ltrace_log_path, 'r') as ltrace_file:
            ltrace_data = ltrace_file.read()
            parsed_ltrace = parse_ltrace_output(ltrace_data)
            json_data['ltrace_analysis'] = summarize_ltrace_data(parsed_ltrace)
    
    # Populate with network analysis data
    if config.get('process_network_analysis', True):
        json_data['network_analysis'] = analyze_network_traffic(pcap_file_path)
    
    # Save to JSON
    save_json(json_data, output_json_path)

# Configuration and Execution

if __name__ == "__main__":
    config = {
        "sample_name": "0a554e1902fdde0519ad509bda10ddbce6c1dabd14b5d17d252aa6520f699c6c",  # Specific sample to process
        "malware_dir": "Malware",  # Directory containing ELF files and logs
        "output_dir": "output/Malware",  # Directory to save JSON output
        "process_strace": True,  # Enable strace processing
        "process_static_analysis": True,  # Process static analysis logs
        "process_ltrace": True,  # Enable ltrace processing
        "process_network_analysis": True  # Enable network analysis
    }
    
    integrate_and_save(config)
