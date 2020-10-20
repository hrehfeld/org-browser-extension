#!/usr/bin/env python3

#TODO: does chrome actually kill the server when it quits?
import json
import sys
import struct
import os
import threading
import queue
from pathlib import Path
import socket
import io
import traceback
import logging
import time
from contextlib import contextmanager

import selectors
import types


# If you use a hostname in the host portion of IPv4/v6 socket address, the program may show a non-deterministic behavior, as Python uses the first address returned from the DNS resolution. The socket address will be resolved differently into an actual IPv4/v6 address, depending on the results from DNS resolution and/or the host configuration. For deterministic behavior use a numeric address in host portion. https://docs.python.org/3/library/socket.html
HOST = '127.0.0.1'
PORT = 43893

LOG_FILEPATH = '/home/hrehfeld/projects/chrome-tabs/server.log'


logging.basicConfig(filename=LOG_FILEPATH,
                    filemode='a',
                    format='%(asctime)s: %(name)s: %(levelname)s: %(message)s', #,%(msecs)d
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG,
                    force=True)


class BrowserSendHandler(logging.Handler):
    def __init__(self, logger):
        logging.Handler.__init__(self)
        self.logger = logger

    def emit(self, record):
        msg = self.format(record)
        self.logger.removeHandler(self)
        browser_send_payload({'type': 'log', 'message': msg})
        self.logger.addHandler(self)


log = logging.getLogger()
#log.addHandler(BrowserSendHandler(log))


def make_EasyLogger(log):
    make_log = lambda logger: lambda _adaptor, *args: logger(' '.join(map(str, args)))
    class EasyLogger:
        debug = make_log(log.debug)
        info = make_log(log.info)
        warning = make_log(log.warning)
        error = make_log(log.error)
    return EasyLogger()


log = make_EasyLogger(log)
browserlog = make_EasyLogger(logging.getLogger('browser'))



class DoQuit(Exception):
    pass


# Encode a message for transmission, given its content.
def encode_message(msg, is_network):
    raw_msg = json.dumps(msg).encode("utf-8")
    length = struct.pack(get_size_binary_format(is_network), len(raw_msg))
    return length + raw_msg


def browser_send_raw(encoded):
    with send_message_lock:
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


message_index_key = 'imessage'
message_payload_key = 'payload'
def make_message(payload):
    message_id = get_message_id()
    msg = { message_payload_key: payload, message_index_key: message_id}
    return message_id, msg


def get_message_id(msg):
    assert message_index_key in msg, msg
    return msg[message_index_key]


send_message_lock = threading.Lock()

def browser_send(msg):
    browser_send_raw(encode_message(msg, is_network=False))


def browser_send_payload(payload):
    _message_id, msg = make_message(payload)
    browser_send(msg)


def browser_receive(message_id):
    response = None
    while not message_quit.is_set() and response is None:
        response = messages_responses.get(message_id, None)
        if response is not None:
            browserlog.debug('found response:', repr(response))
            del messages_responses[message_id]
            break
        # fetch from queue
        try:
            browserlog.debug('Fetching message from queue')
            msg = messages_queue.get(timeout=0.1)
        except queue.Empty:
            break
        assert message_payload_key in msg, msg
        messages_responses[get_message_id(msg)] = msg[message_payload_key]
    return response


def get_size_binary_format(is_network):
    endianess = '!' if is_network else '@'
    return f"{endianess}I"


def read_message_raw(buf, is_network=False, log=log):
    size_len = 4
    # from https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
    if not len(buf) >= size_len:
        return None
    raw_length = buf.peek(4)
    if len(raw_length) == 0:
        raise DoQuit()
    message_length = struct.unpack(get_size_binary_format(is_network), raw_length)[0]
    assert message_length > 0, message_length
    #assert message_length < 16384, message_length

    if len(buf) < size_len + message_length:
        log.debug(f'Skipping message for now: {message_length} + {size_len} > {len(buf)}')
        return None
    buf.skip(size_len)
    message = buf.read(message_length).decode("utf-8")
    message = json.loads(message)
    return message


# main thread
messages_responses = {}
# stdin thread -> main thread
browser_outgoing_messages = queue.SimpleQueue()
editor_outgoing_messages = queue.SimpleQueue()

message_quit = threading.Event()
def message_loop(parse_message):
    try:
        read_buffer = b''
        browserlog.debug('message_loop')
        while not message_quit.is_set():
            try:
                browserlog.info('reading...')
                # use raw so we can iteratively slurp bytes until end
                # non-raw blocks until N bytes were actually send
                chunk = sys.stdin.buffer.raw.read(4096)
                browserlog.info('read', len(chunk), 'bytes')
                if len(chunk) == 0:
                    raise DoQuit()

                read_buffer += chunk

                d = BytesReadAdaptor(read_buffer)
                def success():
                    nonlocal read_buffer
                    read_buffer = d.tail()
                parse_message(d, success, browser_send_raw)
            except DoQuit as e:
                message_quit.set()
                break
            except Exception as e:
                browserlog.error(type(e))
                browserlog.error(e)
    except BaseException as e:
        browserlog.error(type(e))
        browserlog.error(e)
        raise e


class BytesReadAdaptor:
    def __init__(self, byte_data):
        self.byte_data = byte_data
        self.i = 0

    def __len__(self):
        return len(self.byte_data) - self.i

    def __getitem__(self, key):
        i = self.i
        if isinstance(key, slice):
            start = key.start
            if start is None:
                start = 0
            start += i

            stop = key.stop + i
            key = slice(start, stop, key.step)
        else:
            key += i
        return self.byte_data.__getitem__(key)

    def peek(self, num_bytes):
        i = self.i
        iend = i + num_bytes
        ret = self.byte_data[i:iend]
        return ret

    def read(self, num_bytes):
        i = self.i
        iend = i + num_bytes
        ret = self.byte_data[i:iend]
        self.i = iend
        return ret

    def skip(self, num_bytes):
        self.i = self.i + num_bytes

    def tail(self):
        return self.byte_data[self.i:]


class SocketData:
    def __init__(self, addr):
        self.addr = addr
        self.buffer_in = b''
        self.buffer_out = b''


def accept_wrapper(sel, sock):
    conn, addr = sock.accept()  # Should be ready to read
    log.debug('accepted connection from', addr)
    conn.setblocking(False)
    data = SocketData(addr)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)
    return conn


def service_connection(sel, sock, data, mask):
    if mask & selectors.EVENT_READ:
        message = sock.recv(4096)
        if message:
            data.buffer_in += message
        else:
            log.debug('closing connection to', data.addr)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        buffer_out = data.buffer_out
        if buffer_out:
            #log.debug('sending', repr(buffer_out.decode()), 'to', data.addr)
            sent = sock.send(buffer_out)  # Should be ready to write
            data.buffer_out = buffer_out[sent:]


@contextmanager
def run_server(parse_message):
    sel = selectors.DefaultSelector()

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # make socket reuse closed but still not fully closed socket on the same port :o
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.bind((HOST, PORT))
        lsock.listen()
        log.debug('listening on', (HOST, PORT))
        lsock.setblocking(False)
        log.debug('registering', repr(lsock))
        sel.register(lsock, selectors.EVENT_READ, data=None)


        #while not message_quit.is_set():
        def update():
            events = sel.select(timeout=0)
            for key, mask in events:
                sock = key.fileobj
                data = key.data

                # no data means it's a new connection
                if key.data is None:
                    accept_wrapper(sel, sock)
                else:
                    service_connection(sel, sock, data, mask)
                    if data.buffer_in:
                        d = BytesReadAdaptor(data.buffer_in)
                        def success():
                            data.buffer_in = d.tail()

                        def send(byte_data):
                            data.buffer_out += byte_data
                        parse_message(d, success, send)
        yield update

    finally:
        # close all registered sockets
        for isock, _data in sel.get_map().items():
            log.debug('closing', isock)
            socket.close(isock)


def main():
    editor_message_origins_lock = threading.Lock()
    editor_message_origins = {}

    def editor_get_message_origin(key):
        with editor_message_origins_lock:
            return editor_message_origins[key]

    def browser_get_message_origin(key):
        return browser_send

    def set_message_origin(origins, lock):
        def add(key, value):
            with lock:
                origins[key] = value
        return add

    def make_receive_message(set_message_origin, out_queue, log, is_network):
        def receive_message(bytebuf, success, respond_raw):
            message = read_message_raw(bytebuf, is_network=is_network, log=log)
            if message is not None:
                success()
                out_queue.put(message)
                message_id = get_message_id(message)
                log.debug('received:', message_id)
                respond = lambda *args: respond_raw(encode_message(*args, is_network))
                set_message_origin(message_id, respond)
        return receive_message

    browser_set_message_origin = lambda k, v: None
    browser_receive_message = make_receive_message(
        browser_set_message_origin,
        editor_outgoing_messages,
        browserlog,
        is_network=False,
    )
    editor_receive_message = make_receive_message(
        set_message_origin(editor_message_origins, editor_message_origins_lock),
        browser_outgoing_messages,
        log,
        is_network=True,
    )

    message_thread = threading.Thread(None, message_loop, 'message_thread', args=(browser_receive_message,))
    message_thread.daemon = True
    message_thread.start()

    # non threaded
    with run_server(editor_receive_message) as server_update:
        while True:
            server_update()

            def send_messages(out_queue, get_message_origin):
                while not out_queue.empty():
                    try:
                        msg = out_queue.get_nowait()
                    except Empty:
                        break

                    message_id = get_message_id(msg)
                    respond = get_message_origin(message_id)
                    log.debug('sending', respond, message_id)
                    respond(msg)
                    log.debug('done')
            send_messages(editor_outgoing_messages, editor_get_message_origin)
            send_messages(browser_outgoing_messages, browser_get_message_origin)
            time.sleep(0.01)




    message_quit.set()
    raise SystemExit
    message_thread.join()
    return 0



def check_running():
    pid_filepath = Path(__file__).parent / '.pid'

    if pid_filepath.exists():
        with pid_filepath.open('r') as f:
            pid = f.read()
        pid = int(pid)

        import psutil
        for p in psutil.process_iter(attrs=['pid']):
            if p.pid == pid:
                log.debug(f'Killing old process {pid}')
                p.kill()

    pid = os.getpid()
    with pid_filepath.open('w') as f:
        f.write(str(pid))


if __name__ == '__main__':
    check_running()
    debug = len(sys.argv) > 1
    do_quit = False
    while not do_quit:
        try:
            log.debug('-------------------- Start-up --------------------')
            main()
        except (KeyboardInterrupt, DoQuit, SystemExit) as e:
            print(e)
            do_quit = True
            sys.exit(1)
            break
        except BaseException as e:
            estr = str(e)
            backtrace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            log.error(backtrace)
            log.error(estr)

            time.sleep(0.5)
            # don't raise to continue
            #if debug:
            raise e
