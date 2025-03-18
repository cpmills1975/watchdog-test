"""
Monitor for and record file system changes
"""

import logging
import hashlib

from watchdog.events import LoggingEventHandler, FileSystemEvent
from watchdog.observers import Observer

BUF_SIZE = 65535


def hash_file(filename):
    """
    Returns a SHA256 hash for a given filename
    """
    sha = hashlib.sha256()

    try:
        with open(filename, "rb") as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha.update(data)
            return sha.hexdigest()
    except FileNotFoundError:
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


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)


event_handler = MyEventHandler()
observer = Observer()
observer.schedule(event_handler, ".", recursive=True)
observer.schedule(event_handler, "/Volumes/", recursive=True)

observer.start()
try:
    while observer.is_alive():
        observer.join(1)
finally:
    observer.stop()
    observer.join()
