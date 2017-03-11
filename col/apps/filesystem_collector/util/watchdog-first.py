import sys
import time
from logging import INFO, basicConfig
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler

if __name__ == "__main__":
    basicConfig(level   = INFO,
                format  = '%(asctime)s - %(message)s',
                datefmt = '%Y-%m-%d %H:%M:%S')
    path = sys.argv[1]
    event_handler = LoggingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
