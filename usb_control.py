from __future__ import annotations

from abc import ABC, abstractmethod

import threading
import subprocess
import json
from warnings import warn

import logging
import hashlib

from watchdog.events import LoggingEventHandler, FileSystemEvent
from watchdog.observers import Observer


_SECONDS_BETWEEN_CHECKS = 1
_THREAD_JOIN_TIMEOUT_SECONDS = 5

_BUF_SIZE = 65535


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
LOGGER = logging.getLogger(__name__)


class _DiskMonitor(ABC):
    def __init__(
        self, filter_disks: list[dict[str, str]] | tuple[dict[str, str]] = None
    ):
        """
        Initialises the DiskMonitor class
        """
        self._thread = None
        self.filter_disks = filter_disks
        self._stop_thread = threading.Event()

        if filter_disks is not None:
            assert isinstance(filter_disks, (list, tuple)), (
                f"filter_disks must be a list or a tuple of dicts "
                f"(or None). Got {type(filter_disks)}"
            )
            assert all(isinstance(disk, dict) for disk in filter_disks), (
                f"filter_disks must contain dicts. "
                f"Got {set(type(disk) for disk in filter_disks)}"
            )

        self.on_start_disks = self.get_mounted_disks()
        self.last_check_disks = self.on_start_disks.copy()

    def changes_from_last_check(
        self, update_last_check_disks: bool = True
    ) -> tuple[dict[str, str], dict[str, str]]:
        """
        Returns a tuple of two tuples. The first containing the disk names of the
        disks that were unmounted, the second containing the device names of the disks
        that were mounted.
        """
        current_disks, previous_disks = self.get_mounted_disks(), self.last_check_disks

        # Get the difference between the current disks and the previous disks
        removed_disks = {
            _name: _info
            for _name, _info in previous_disks.items()
            if _name not in current_disks
        }
        added_disks = {
            _name: _info
            for _name, _info in current_disks.items()
            if _name not in previous_disks
        }

        # Update the last checked disks to current if requested
        if update_last_check_disks:
            self.last_check_disks = current_disks.copy()
        return removed_disks, added_disks

    @abstractmethod
    def __get_disks(self):
        pass

    def get_mounted_disks(self) -> dict[str, dict[str, str]]:
        """
        Returns a dictionary of mounted disks keyed by the disk name
        """
        disk_info = self.__get_disks()
        if self.filter_disks is not None:
            disk_info = self._apply_disk_filter(disks=disk_info)
        return disk_info

    def _apply_disk_filter(
        self, disks: dict[str, dict[str, str | tuple[str, ...]]]
    ) -> dict[str, dict[str, str | tuple[str, ...]]]:
        """
        Filters the disks by the given filters. Only disks that match all the filters
        in any of the dicts will be returned.
        """
        for disk_name, disk_info in disks.copy().items():
            # Iterate over each filter dict
            for filter_dict in self.filter_disks:
                if all(disk_info[key] == value for key, value in filter_dict.items()):
                    break
                else:
                    disks.pop(disk_name)
        return disks

    def check_changes(
        self,
        on_mount: callable | None = None,
        on_unmount: callable | None = None,
        update_last_check_disks: bool = True,
    ) -> None:
        """
        Checks for changes in mounted disks and fires the on_mount and on_unmount
        callables when changes are detected
        """
        unmounted_disks, mounted_disks = self.changes_from_last_check(
            update_last_check_disks=update_last_check_disks
        )
        if on_unmount is not None:
            for disk_name, disk_info in unmounted_disks.items():
                on_unmount(disk_name, disk_info)
        if on_mount is not None:
            for disk_name, disk_info in mounted_disks.items():
                on_mount(disk_name, disk_info)

    def start_monitoring(
        self,
        on_mount: callable | None = None,
        on_unmount: callable | None = None,
        check_interval: int | float = _SECONDS_BETWEEN_CHECKS,
    ) -> None:
        """
        Starts monitoring the list of mounted disks.
        """
        assert self._thread is None, "The disk monitor is already running"
        self._thread = threading.Thread(
            name="Disk Monitor",
            target=self._monitor_changes,
            args=(on_mount, on_unmount, check_interval),
            daemon=True,
        )
        self._thread.start()

    def stop_monitoring(
        self,
        warn_if_was_stopped: bool = True,
        warn_if_timeout: bool = True,
        timeout=_THREAD_JOIN_TIMEOUT_SECONDS,
    ) -> None:
        """
        Stops monitoring the list of mounted disks
        """
        if self._thread is not None:
            self._stop_thread.set()
            self._thread.join(timeout=timeout)
            if warn_if_timeout and self._thread.is_alive():
                warn(
                    f"Disk monitor thread did not stop in {timeout} seconds. "
                    "It could still be running.",
                    RuntimeWarning,
                )
            self._thread = None
        elif warn_if_was_stopped:
            warn(
                "Disk monitor cannot be stopped because it is not running",
                RuntimeWarning,
            )
        self._stop_thread.clear()

    def _monitor_changes(
        self,
        on_mount: callable | None = None,
        on_unmount: callable | None = None,
        check_every_seconds: int | float = _SECONDS_BETWEEN_CHECKS,
    ) -> None:
        """
        Monitors for changes in the mounted disks. Should always be called on
        a background thread
        """
        while not self._stop_thread.is_set():
            self.check_changes(on_mount=on_mount, on_unmount=on_unmount)
            self._stop_thread.wait(check_every_seconds)

    def __del__(self):
        self.stop_monitoring(warn_if_was_stopped=False)


class DarwinDiskMonitor(_DiskMonitor):
    """
    MacOS implementation of DiskMonitor
    """

    def __init__(self):
        return super().__init__()

    def __get_disks(self) -> dict[str, dict[str, str]]:
        """
        Retrieves the list of disks using the system_profiler
        command.
        """
        disks = {}

        try:
            profiler_command_output = subprocess.check_output(
                ["system_profiler", "-json", "SPStorageDataType"], text=True
            )
        except subprocess.CalledProcessError as e:
            warn(f"Failed to retrieve disk information {e}")
            return {}

        try:
            disks_info = json.loads(profiler_command_output)["SPStorageDataType"]
        except KeyError:
            warn("Failed to parse disk information")
            return {}

        for disk_dict in disks_info:
            name = disk_dict.get("_name", "")
            physical = disk_dict.get("physical_drive", {})
            del disk_dict["physical_drive"]
            disks[name] = disk_dict | physical

        return disks


observed_paths = {}


def hash_file(filename):
    """
    Returns a SHA256 hash for a given filename
    """
    sha = hashlib.sha256()

    try:
        with open(filename, "rb") as f:
            while True:
                data = f.read(_BUF_SIZE)
                if not data:
                    break
                sha.update(data)
            return sha.hexdigest()
    except (FileNotFoundError, PermissionError):
        return "Unknown"


class MyEventHandler(LoggingEventHandler):
    """
    Subclass of LoggingEventHandler adding output of a file hash
    when a file is modified.
    """

    def on_modified(self, event: FileSystemEvent) -> None:
        """
        Called in response to a file being modified
        """
        if event.is_directory:
            self.logger.info("Modified directory: %s", event.src_path)
        else:
            path = event.dest_path if len(event.dest_path) > 0 else event.src_path
            self.logger.info(
                "Modified file: %s (%s)",
                path,
                hash_file(path),
            )


def add_observed_endpoint(filepath: str) -> None:
    LOGGER.info("Adding observed endpoint %s", filepath)
    observed_paths[filepath] = observer.schedule(
        event_handler, filepath, recursive=True
    )


def remove_observed_endpoint(filepath: str) -> None:
    try:
        observer.unschedule(observed_paths[filepath])
        LOGGER.info("Removing observed endpoint %s", filepath)
    except KeyError:
        pass


def do_mount(_: str, disk_info: dict[str, str]) -> None:
    mount_point = disk_info.get("mount_point", None)
    if mount_point is not None:
        add_observed_endpoint(mount_point)


def do_unmount(_: str, disk_info: dict[str, str]) -> None:
    mount_point = disk_info.get("mount_point", None)
    if mount_point is not None:
        remove_observed_endpoint(mount_point)


disk_monitor = DarwinDiskMonitor(filter_disks=[{"protocol": "USB"}])
disk_monitor.start_monitoring(on_mount=do_mount, on_unmount=do_unmount)
event_handler = MyEventHandler(logger=LOGGER)
observer = Observer()
observer.start()
try:
    while observer.is_alive():
        observer.join(1)
finally:
    observer.stop()
    observer.join()
