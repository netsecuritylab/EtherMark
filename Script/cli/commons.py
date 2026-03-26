import sys
import time
import itertools
from contextlib import contextmanager
import threading
from config.constants import STR_CMD_SUCCESS, STR_CMD_ERROR, STR_PREFIX


def spinner(stop_event, msg: str):
    l = 4
    msgs = [f"{STR_PREFIX} {msg}{'.'*i}" for i in range(l)]
    msgs.append(f"{STR_PREFIX} {msg}{' '*(l-1)}")

    for k in itertools.cycle(range(len(msgs))):
        if stop_event.is_set():
            break
        sys.stdout.write(f"\r{msgs[k]}")
        sys.stdout.flush()
        time.sleep(0.5)


@contextmanager
def spinning(message="Processing...", length: int = len("Processing...")):
    stop_event = threading.Event()
    dot_len = length - len(message) - 1
    t = threading.Thread(target=spinner, args=(stop_event, message))
    t.start()
    try:
        yield
    except BaseException as e:
        stop_event.set()
        t.join()
        sys.stdout.write(f"\r[{STR_CMD_ERROR}] {message}{'.'*dot_len}: Failed!\n")
        raise
    else:
        stop_event.set()
        t.join()
        sys.stdout.write(f"\r[{STR_CMD_SUCCESS}] {message}{'.'*dot_len}: Done!\n")

def compute_percentage(stop_event, msg: str, max_val: int, status_fn):
    while not stop_event.is_set():
        sys.stdout.write(f"\r{msg}    ")
        sys.stdout.write(f"\r{msg} {int(status_fn()/max_val * 100):3d}%")
        sys.stdout.flush()
        time.sleep(0.5)

@contextmanager
def percentage(message="Processing...", max_val: int = 100, status_fn=None):
    stop_event = threading.Event()
    t = threading.Thread(target=compute_percentage, args=(stop_event, message, max_val, status_fn))
    t.start()
    try:
        yield
    except BaseException as e:
        stop_event.set()
        t.join()
        sys.stdout.write(f"\r[{STR_CMD_ERROR}] {message} Failed!\n")
        raise
    else:
        stop_event.set()
        t.join()
        sys.stdout.write(f"\r[{STR_CMD_SUCCESS}] {message} Done!\n")

def print_separator_line(l: int):
    print(f"{STR_PREFIX} +{'-+' * l}")

def print_with_prefix(msg: str):
    print(f"{STR_PREFIX} {msg}")