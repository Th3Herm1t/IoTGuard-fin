import hashlib
import subprocess
import datetime
import docker
import os
import logging
import shutil
import time
import psutil
import re
from collections import Counter
from typing import List, Optional

def setup_logging(log_file_path: str):
    """Configures logging to log to a specific file and the console."""
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    logging.basicConfig(level=logging.INFO, 
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_file_path),
                            logging.StreamHandler()
                        ])

class DockerManager:
    """Manages Docker container operations."""

    def __init__(self, container_name: str, host_dir: str, container_dir: str):
        self.client = docker.from_env()
        self.container_name = container_name
        self.host_dir = host_dir
        self.container_dir = container_dir
        self.container = self._get_or_create_container()

    def _get_or_create_container(self):
        """Gets or creates a Docker container."""
        try:
            container = self.client.containers.get(self.container_name)
            if container.status != "running":
                container.start()
                logging.info(f"Container '{self.container_name}' started.")
            return container
        except docker.errors.NotFound:
            logging.info(f"Container '{self.container_name}' not found. Creating a new container...")
            return self.client.containers.run(
                image="arm-elf-analysis",
                name=self.container_name,
                volumes={self.host_dir: {'bind': self.container_dir, 'mode': 'rw'}},
                detach=True,
                tty=True
            )
        except docker.errors.APIError as e:
            logging.error(f"API error occurred while getting/creating container '{self.container_name}': {e}")
            raise
        except Exception as e:
            logging.exception(f"Unexpected error while getting/creating container '{self.container_name}': {e}")
            raise

    def execute_command(self, command: str, detach: bool = False):
        """Executes a command inside the Docker container."""
        try:
            exec_id = self.client.api.exec_create(self.container.id, cmd=f'sh -c "{command}"')
            result = self.client.api.exec_start(exec_id, detach=detach)
            logging.info(f"Executed command: {command}")
            return exec_id if detach else result
        except docker.errors.APIError as e:
            logging.error(f"Error executing command '{command}': {e}")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error occurred while executing command '{command}': {e}")
            return None

    def inspect_exec(self, exec_id):
        """Inspects the execution of a command in the container."""
        try:
            return self.client.api.exec_inspect(exec_id)
        except docker.errors.APIError as e:
            logging.error(f"Error inspecting execution '{exec_id}': {e}")
            return None
        except Exception as e:
            logging.exception(f"Unexpected error occurred while inspecting execution '{exec_id}': {e}")
            return None

    def stop_and_remove_container(self):
        """Stops and removes the Docker container."""
        try:
            if self.container:
                self.container.stop()
                self.container.remove()
                logging.info(f"Container '{self.container_name}' stopped and removed.")
        except docker.errors.APIError as e:
            logging.error(f"API error occurred while stopping/removing container '{self.container_name}': {e}")
        except Exception as e:
            logging.exception(f"Unexpected error while stopping/removing container '{self.container_name}': {e}")

class ARMAnalyzer:
    """Analyzes ARM ELF files using Docker container."""

    def __init__(self, docker_manager: DockerManager, progress_tracker: 'ProgressTracker', apply_patch: bool = False):
        self.docker_manager = docker_manager
        self.progress_tracker = progress_tracker
        self.apply_patch = apply_patch  # New attribute to control patching

    def analyze_elf(self, elf_path: str, output_path: str, timeout: int = 30, poll_interval: int = 5):
        """Performs ELF file analysis inside a Docker container."""
        sample_name = os.path.basename(elf_path)

        if self.progress_tracker.is_processed(sample_name):
            logging.info(f"Sample '{sample_name}' has already been processed. Skipping...")
            return

        # Normalize paths
        elf_path = os.path.normpath(elf_path)
        output_path = os.path.normpath(output_path)
        
        # Set up logging for the current sample
        sample_dir = os.path.dirname(output_path)
        log_file_path = os.path.join(sample_dir, "analysis.log")
        setup_logging(log_file_path)

        try:
            logging.info(f"Analyzing: {elf_path}")
            
            # Record start time
            start_time = time.time()

            # Log basic file information
            self.log_file_metadata(elf_path)

            # Apply patching if needed
            if self.apply_patch:
                logging.info("Patching ELF file before analysis...")
                self.patch_elf(elf_path)

            # Static analysis before execution
            static_analysis_log = output_path.replace('_strace.log', '_static_analysis.log')
            self.perform_static_analysis(elf_path, static_analysis_log)

            # Log system info before execution
            self.log_system_info("before")

            # Backup the ELF file
            backup_file = self.create_backup(elf_path)

            # Check for tshark existence and run it if available
            tshark_output_path = output_path.replace('_strace.log', '_tshark.pcap')
            tshark_pid = self.start_tshark(tshark_output_path)

            # Execute ELF with strace
            self.run_strace_analysis(backup_file, output_path, timeout, poll_interval)

            # Stop tshark if it was started
            if tshark_pid:
                self.stop_tshark(tshark_pid)

            # Log system info after execution
            self.log_system_info("after")

            # Clean up the backup file
            self.cleanup_backup(backup_file)

            # Perform ltrace analysis
            ltrace_summary = self.run_ltrace_analysis(backup_file)
            if ltrace_summary:
                ltrace_output_path = output_path.replace('_strace.log', '_ltrace_summary.log')
                self.save_ltrace_summary(ltrace_summary, ltrace_output_path)

            # Record end time
            end_time = time.time()
            
            # Calculate the time taken
            time_taken = end_time - start_time
            
            # Mark sample as processed with the time taken
            self.progress_tracker.mark_as_processed(sample_name, time_taken)

        except Exception as e:
            logging.exception(f"Unexpected error during ELF analysis: {e}")

    def patch_elf(self, elf_path: str):
        """Patches the ELF file to set the interpreter before execution."""
        try:
            container_elf_path = self.windows_to_container_path(elf_path)
            patch_command = f'patchelf --set-interpreter /usr/arm-linux-gnueabihf/lib/ld-linux.so.3 {container_elf_path}'
            logging.info(f"Patching ELF with command: {patch_command}")
            self.docker_manager.execute_command(patch_command)
            logging.info("ELF patching completed successfully.")
        except Exception as e:
            logging.exception(f"Error patching ELF file: {e}")

    def run_strace_analysis(self, elf_path: str, output_path: str, timeout: int, poll_interval: int):
        """Runs strace analysis on the ELF file inside the container."""
        try:
            container_elf_path = self.windows_to_container_path(elf_path)
            container_output_path = self.windows_to_container_path(output_path)

            # Modify the command to use the patched interpreter if apply_patch is active
            if self.apply_patch:
                command = f'qemu-arm -L /usr/arm-linux-gnueabihf/ -strace {container_elf_path} > {container_output_path} 2>&1'
            else:
                command = f'qemu-arm -L /usr/arm-linux-gnueabihf/ -strace {container_elf_path} > {container_output_path} 2>&1'

            logging.info(f"Running strace command: {command}")

            exec_id = self.docker_manager.execute_command(command, detach=True)
            if exec_id:
                if self.wait_for_completion(exec_id, timeout, poll_interval):
                    logging.info(f"Strace analysis completed. Output saved to {output_path}")
                else:
                    logging.error(f"Strace command timed out after {timeout} seconds.")
                    self.docker_manager.container.kill()
            else:
                logging.error(f"Failed to execute strace command.")

        except Exception as e:
            logging.exception(f"Unexpected error during strace analysis: {e}")
        
    def start_tshark(self, output_path: str) -> Optional[str]:
        """Starts tshark to capture network traffic if tshark is available."""
        try:
            # Check if tshark is installed in the container
            check_command = "command -v tshark"
            result = self.docker_manager.execute_command(check_command)
            if not result.strip():
                logging.error("tshark is not installed in the container. Skipping network capture.")
                return None

            container_output_path = self.windows_to_container_path(output_path)
            # Capture full packets and write them to a file using tshark
            command = f'tshark -i any -s 65535 -w {container_output_path}'
            logging.info(f"Starting tshark with command: {command}")

            exec_id = self.docker_manager.execute_command(command, detach=True)
            if exec_id:
                logging.info(f"tshark started with exec_id: {exec_id}")
                return exec_id
            else:
                logging.error("Failed to start tshark.")
                return None

        except Exception as e:
            logging.exception(f"Unexpected error starting tshark: {e}")
            return None

    def stop_tshark(self, exec_id: Optional[str]):
        """Stops the tshark process."""
        try:
            if exec_id:
                # Use SIGINT to gracefully stop tshark
                self.docker_manager.execute_command(f"kill -SIGINT {exec_id}")
                logging.info("tshark stopped successfully.")
            else:
                logging.warning("No tshark process to stop.")
        except Exception as e:
            logging.error(f"Error stopping tshark: {e}")

    def create_backup(self, file_path: str) -> str:
        """Creates a backup of the ELF file."""
        try:
            # Normalize the file path to ensure consistent formatting
            file_path = os.path.normpath(file_path)
            
            # Generate a backup file path
            backup_file = f"{file_path}_backup.elf"
            
            # Normalize the backup file path as well
            backup_file = os.path.normpath(backup_file)
            
            # Copy the original file to the backup location
            shutil.copy(file_path, backup_file)
            
            logging.info(f"Backup of ELF created at: {backup_file}")
            return backup_file
        except Exception as e:
            logging.error(f"Error creating backup of ELF file: {e}")
            raise

    def cleanup_backup(self, backup_file: str):
        """Removes the backup file."""
        try:
            if os.path.exists(backup_file):
                os.remove(backup_file)
                logging.info(f"Backup file {backup_file} has been deleted.")
        except Exception as e:
            logging.error(f"Error cleaning up backup file {backup_file}: {e}")

    def wait_for_completion(self, exec_id: str, timeout: int, poll_interval: int) -> bool:
        """Waits for a command to complete with a specified timeout and polling interval."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            exec_inspect = self.docker_manager.inspect_exec(exec_id)
            if exec_inspect and not exec_inspect['Running']:
                return True
            logging.info("Command still running... checking again after interval.")
            time.sleep(poll_interval)
        return False

    def run_ltrace_analysis(self, elf_path: str) -> Optional[str]:
        """Runs ltrace analysis on the ELF file inside the container."""
        try:
            logging.info("Running ltrace analysis...")

            container_elf_path = self.windows_to_container_path(elf_path)
            container_dir = os.path.dirname(container_elf_path)
            elf_filename = os.path.basename(container_elf_path)

            ltrace_command = f'cd {container_dir} && ltrace -o ltrace_output.txt qemu-arm {elf_filename}'

            exec_id = self.docker_manager.execute_command(ltrace_command)
            if exec_id:
                if self.wait_for_completion(exec_id, timeout=300, poll_interval=5):
                    ltrace_output = self.docker_manager.execute_command(f'cat {container_dir}/ltrace_output.txt').decode('utf-8')
                    self.docker_manager.execute_command(f'rm {container_dir}/ltrace_output.txt')
                    return self.summarize_ltrace_output(ltrace_output)
                else:
                    logging.error("Ltrace command timed out.")
        except Exception as e:
            logging.exception(f"Unexpected error during ltrace analysis: {e}")
            return None

    def summarize_ltrace_output(self, ltrace_output: str) -> str:
        """Summarizes the ltrace output."""
        logging.info("Summarizing ltrace output...")

        try:
            lines = ltrace_output.splitlines()
            function_calls = Counter()

            for line in lines:
                match = re.match(r'(\w+)\(', line)
                if match:
                    function_calls[match.group(1)] += 1

            if not function_calls:
                logging.warning("No function calls detected in ltrace output.")
                return ""

            summary = "ltrace Summary:\n================\n"
            summary += "\n".join(f"{func}: {count} calls" for func, count in function_calls.most_common(10))

            logging.info("ltrace summary generated successfully.")
            return summary

        except Exception as e:
            logging.error(f"Error summarizing ltrace output: {e}")
            return ""

    def save_ltrace_summary(self, summary: str, output_path: str):
        """Saves the ltrace summary to a file."""
        if summary:
            try:
                with open(output_path, 'w') as f:
                    f.write(summary)
                logging.info(f"ltrace summary saved to: {output_path}")
            except Exception as e:
                logging.error(f"Failed to save ltrace summary to {output_path}: {e}")
        else:
            logging.warning("No ltrace summary to save.")

    def perform_static_analysis(self, elf_path: str, output_path: str):
        """Performs static analysis on the ELF file using readelf and objdump."""
        try:
            logging.info(f"Performing static analysis on: {elf_path}")
            container_elf_path = self.windows_to_container_path(elf_path)
            container_output_path = self.windows_to_container_path(output_path)

            command = f'readelf -a {container_elf_path} > {container_output_path} && objdump -d {container_elf_path} >> {container_output_path}'
            self.docker_manager.execute_command(command)
            logging.info(f"Static analysis output saved to: {output_path}")
        except Exception as e:
            logging.error(f"Error performing static analysis on {elf_path}: {e}")

    def log_file_metadata(self, file_path: str):
        """Logs metadata of the ELF file."""
        try:
            logging.info(f"Logging file metadata for: {file_path}")
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            sha256_hash = self.calculate_hash(file_path)

            logging.info(f"File Metadata: Size: {file_size}, SHA256 Hash: {sha256_hash}, "
                         f"Permissions: {oct(file_stat.st_mode)}, Created: {datetime.datetime.fromtimestamp(file_stat.st_ctime)}, "
                         f"Last Modified: {datetime.datetime.fromtimestamp(file_stat.st_mtime)}")
        except OSError as e:
            logging.error(f"Error logging file metadata: {e}")

    def calculate_hash(self, file_path: str) -> str:
        """Calculates SHA256 hash of the file."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating SHA256 hash for {file_path}: {e}")
            return ""

    def log_system_info(self, timing: str):
        """Logs system information before and after execution."""
        try:
            logging.info(f"Logging system information ({timing})...")
            cpu_load = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            logging.info(f"System Info ({timing}): CPU Load: {cpu_load}%, Memory Usage: {memory.percent}%, Disk Usage: {disk.percent}%, "
                         f"Available Memory (MB): {memory.available / (1024**2)}, Available Disk Space (GB): {disk.free / (1024**3)}")
        except psutil.Error as e:
            logging.error(f"Error logging system information: {e}")

    def windows_to_container_path(self, windows_path: str) -> str:
        """Converts a Windows file path to a corresponding path in the Docker container."""
        try:
            windows_path = windows_path.replace('\\', '/')
            host_dir = self.docker_manager.host_dir.replace('\\', '/')

            if windows_path.startswith(host_dir):
                relative_path = windows_path[len(host_dir):].lstrip('/')
                return f"{self.docker_manager.container_dir}/{relative_path}"
            else:
                raise ValueError(f"Path {windows_path} is not within the mounted directory {host_dir}")
        except Exception as e:
            logging.error(f"Error converting Windows path to container path: {e}")
            raise

class ProgressTracker:
    """Tracks the progress of analyzed samples."""
    
    def __init__(self, progress_file: str):
        self.progress_file = progress_file
        self.processed_samples = self._load_progress()

    def _load_progress(self) -> set:
        """Loads the list of already processed samples from the progress file."""
        if os.path.exists(self.progress_file):
            with open(self.progress_file, 'r') as file:
                return set(line.split(' - ')[0].strip() for line in file)
        return set()

    def is_processed(self, sample_name: str) -> bool:
        """Checks if a sample has already been processed."""
        return sample_name in self.processed_samples

    def mark_as_processed(self, sample_name: str, time_taken: float):
        """Marks a sample as processed and updates the progress file."""
        entry = f"{sample_name} - Time taken: {time_taken:.2f} seconds"
        self.processed_samples.add(sample_name)
        with open(self.progress_file, 'a') as file:
            file.write(f"{entry}\n")
        logging.info(f"Marked sample '{sample_name}' as processed. Time taken: {time_taken:.2f} seconds")

def main(config: dict):
    # Initialize DockerManager
    docker_manager = DockerManager(
        container_name=config['container_name'],
        host_dir=config['host_dir'],
        container_dir=config['container_dir']
    )

    # Initialize ProgressTracker
    progress_tracker = ProgressTracker(os.path.join(config['malware_dir'], 'processed_samples.txt'))

    # Initialize ARMAnalyzer with DockerManager, ProgressTracker, and the patching option
    analyzer = ARMAnalyzer(docker_manager, progress_tracker, apply_patch=config.get('apply_patch', False))

    try:
        # Get list of sample directories
        sample_dirs = sorted(os.listdir(config['malware_dir']))

        if config.get('specific_samples'):
            sample_dirs = [s for s in sample_dirs if s in config['specific_samples']]
        elif config.get('num_samples'):
            sample_dirs = sample_dirs[:config['num_samples']]

        for sample_dir in sample_dirs:
            #time.sleep(30)
            sample_path = os.path.join(config['malware_dir'], sample_dir)
            elf_file = os.path.join(sample_path, f"{sample_dir}.elf")

            if os.path.exists(elf_file):
                output_file = os.path.join(sample_path, f"{sample_dir}_strace.log")
                analyzer.analyze_elf(elf_file, output_file)
            else:
                logging.warning(f"ELF file not found for sample: {sample_dir}")

    finally:
        # Stop and remove the Docker container
        docker_manager.stop_and_remove_container()

if __name__ == "__main__":
    config = {
        "container_name": "iotguard-analysis",
        "host_dir": "C:/Users/abdel/Desktop/IoTGuard",
        "container_dir": "/app/IoTGuard",
        "malware_dir": "C:/Users/abdel/Desktop/IoTGuard/Benign",
        "specific_samples": None,
        "num_samples": 918,
        "apply_patch": False  # Enable ELF patching before analysis
    }

    main(config)