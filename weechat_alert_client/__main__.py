#!/usr/bin/env python3

# Copyright 2019 by Paul Goins.
#
# This file is part of weechat_alert_client.
#
# weechat_alert_client is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# weechat_alert_client is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with weechat_alert_client.  If not, see
# <https://www.gnu.org/licenses/>.

import argparse
import datetime
import os
import pprint
import socket
import ssl
import stat
import struct
import sys
import zlib

CHUNK_SIZE = 4096
DEBUG = False

CHANNEL_DICT = {}
FORMAT = None


def main():
    global FORMAT
    args = parse_args()
    password = get_password()
    FORMAT = args.format
    s = get_socket(args)

    commands = ''.join([
        f'init password={password}\n',
        '(channel_list) hdata buffer:gui_buffers(*) name\n',
        'sync * buffer\n',
    ])

    if DEBUG:
        print(commands)
    s.send(commands.encode())
    buffer = b""
    try:
        while True:
            chunk = s.recv(CHUNK_SIZE)
            if len(chunk) == 0:
                if DEBUG:
                    print('EOF received')
                break  # EOF received
            if DEBUG:
                print(f'Received {len(chunk)} bytes')
            buffer += chunk
            buffer = handle_buffer(buffer, line_added_message_handler)
    except KeyboardInterrupt:
        if DEBUG:
            print('Ctrl-C detected')
    finally:
        if DEBUG:
            print('closing')
        s.close()


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('remote_host')
    ap.add_argument('remote_port', type=int)
    ap.add_argument('-s', '--ssl', default=False, action='store_true')
    ap.add_argument('-c', '--cacert-path', help='If provided, will use this PEM-formatted certificate file as a cacert authority.')
    ap.add_argument('-f', '--format', help='Message format.  May contain {timestamp}, {channel}, {nick} and {message} variables.  Uses Python str.format() for formatting.  (Default: %(default)s)',
                    default='[{timestamp}] {channel} <{nick}> {message}')
    return ap.parse_args()


def get_password():
    password_file = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, 'password'))
    if not os.path.exists(password_file):
        print(f'{password_file} does not yet exist.  Please create the file, supply the password to your bouncer, and "chmod 600" it.', file=sys.stderr)
        sys.exit(1)
    if (os.stat(password_file).st_mode & (stat.S_IROTH | stat.S_IRGRP)) != 0:
        print(f'{password_file} is either group or world readable; Please "chmod 600" the file.', file=sys.stderr)
        sys.exit(1)
    with open(password_file) as infile:
        return infile.read().strip()


def get_socket(args):
    if args.ssl:
        ssl_context = create_ssl_context(args.cacert_path)
    else:
        ssl_context = None
    s = socket.create_connection((args.remote_host, args.remote_port))
    if ssl_context:
        s = ssl_context.wrap_socket(s)
    return s


def create_ssl_context(cacert_path):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cacert_path:
        ssl_context.load_verify_locations(cacert_path)
    else:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return ssl_context


def handle_buffer(buffer, message_handler):
    message_ready, size = check_buffer_for_message(buffer)
    if not message_ready:
        return buffer

    # We have a full object.
    new_buffer = buffer[size:]
    payload = get_payload(buffer, size)
    message_handler(payload)
    return new_buffer


def check_buffer_for_message(buffer):
    message_ready = False
    size = None
    if len(buffer) >= 4:
        size = extract_int(buffer, 0)[0]
        if len(buffer) >= size:
            message_ready = True
    return message_ready, size


def get_payload(buffer, size):
    compressed = buffer[4]
    payload = buffer[5:size]
    if compressed:
        payload = zlib.decompress(payload)
    return payload


def line_added_message_handler(payload):
    pos = 0
    id_, pos = extract_str(payload, pos)

    if DEBUG:
        print('--------------------------------')
        print('Message start')
        print('id:', id_)

    while pos < len(payload):
        type_, pos = extract_type(payload, pos)
        extractor = get_extractor(type_)
        o, pos = extractor(payload, pos)
        # NOTE: o is an hdata object, unless noted otherwise.

        if DEBUG:
            pprint.pprint(o)

        if id_ == 'channel_list':
            for ptr_, values in o['items']:
                # ptr_ is always single item here
                CHANNEL_DICT[ptr_[0]] = values['name']

        elif id_ == '_buffer_opened':
            for ptr_, values in o['items']:
                # ptr_ is always single item here
                CHANNEL_DICT[ptr_[0]] = values['full_name']

        elif id_ == '_buffer_renamed':
            for ptr_, values in o['items']:
                # ptr_ is always single item here
                CHANNEL_DICT[ptr_[0]] = values['local_variables']['name']

        elif id_ == '_buffer_line_added':
            # o is an hdata object
            for ptr_, values in o['items']:
                highlighted = values['highlight'] != '\x00'
                nick = get_nick(values['tags_array'])
                channel = CHANNEL_DICT[values['buffer']]
                if highlighted or 'notify_private' in values['tags_array']:
                    timestamp = datetime.datetime.utcfromtimestamp(values['date']).strftime('%m-%d %H:%M:%S')
                    message = values['message']
                    # ALSO GOOD TO INCLUDE: The channel name!
                    # (Seems we have a buffer pointer; need to look up where it comes from.)
                    print(FORMAT.format(timestamp=timestamp, channel=channel, nick=nick, message=message))

    if DEBUG:
        print('Message end')
        print('--------------------------------')


def get_nick(tags):
    for tag in tags:
        if tag.startswith('nick_'):
            return tag.split('_', 1)[1]
    return None


def extract_type(buffer, pos):
    result = buffer[pos:pos+3].decode()
    return result, pos + 3


def extract_chr(buffer, pos):
    return chr(buffer[pos]), pos + 1


def extract_int(buffer, pos):
    i = struct.unpack_from('>i', buffer, pos)[0]
    return i, pos + 4


def extract_lon(buffer, pos):
    size = buffer[pos]
    pos += 1
    long = int(buffer[pos:pos+size].decode())
    return long, pos + size


def extract_str(buffer, pos):
    b, pos = extract_buf(buffer, pos)
    if b is not None:
        s = b.decode()
    else:
        s = None
    return s, pos


def extract_buf(buffer, pos):
    size, pos = extract_int(buffer, pos)
    if size >= 0:
        b = buffer[pos:pos + size]
    else:
        b = None
        size = 0
    return b, pos + size


def extract_ptr(buffer, pos):
    size = buffer[pos]
    pos += 1
    if size == 1 and buffer[pos] == 0:
        ptr = None
    else:
        ptr = int(buffer[pos:pos+size].decode(), 16)
    return ptr, pos + size


extract_tim = extract_lon


def extract_arr(buffer, pos):
    type_, pos = extract_type(buffer, pos)
    count, pos = extract_int(buffer, pos)

    result = []
    extractor = get_extractor(type_)
    for i in range(count):
        o, pos = extractor(buffer, pos)
        result.append(o)

    return result, pos


def extract_htb(buffer, pos):
    key_type, pos = extract_type(buffer, pos)
    value_type, pos = extract_type(buffer, pos)
    count, pos = extract_int(buffer, pos)

    result = {}
    key_extractor = get_extractor(key_type)
    value_extractor = get_extractor(value_type)
    for i in range(count):
        key, pos = key_extractor(buffer, pos)
        value, pos = value_extractor(buffer, pos)
        result[key] = value

    return result, pos


def extract_hda(buffer, pos):
    # The docs are *not* clear here, unfortunately.
    # I get the feeling there's an error in their "lines of core buffer" example
    # where the p-path length is different between objects in the same set.
    # Doing the best I can with what I can figure out here...
    h_path, pos = extract_str(buffer, pos)
    keys, pos = extract_str(buffer, pos)
    if DEBUG:
        print('KEYS:', keys)
    count, pos = extract_int(buffer, pos)

    p_path_size = len(h_path.split('/'))
    key_tokens = [token.split(':') for token in keys.split(',')]

    items = []
    for i in range(count):
        p_path = []
        for j in range(p_path_size):
            ptr, pos = extract_ptr(buffer, pos)
            p_path.append(ptr)
        value_d = {}
        for name, type_ in key_tokens:
            extractor = get_extractor(type_)
            value, pos = extractor(buffer, pos)
            value_d[name] = value
        # p_path can be more easily used as a dictionary key if we convert it
        # to a tuple.
        items.append([tuple(p_path), value_d])

    hda = {
        'h_path': h_path,
        'items': items,
    }
    return hda, pos


def extract_inf(buffer, pos):
    print('NOTE: INF received!  (Not tested yet...)')
    name, pos = extract_str(buffer, pos)
    value, pos = extract_str(buffer, pos)
    return [name, value], pos


def extract_inl(buffer, pos):
    print('NOTE: INL received!  (Not tested yet...)')
    infolist_name, pos = extract_str(buffer, pos)
    infolist_size, pos = extract_int(buffer, pos)
    items = []
    for i in range(infolist_size):
        item_size, pos = extract_int(buffer, pos)
        item = []
        for j in range(item_size):
            name, pos = extract_str(buffer, pos)
            type_, pos = extract_type(buffer, pos)
            extractor = get_extractor(type_)
            value, pos = extractor(buffer, pos)
            item.append([name, value])
        items.append(item)
    return items


def get_extractor(type_):
    return globals()[f'extract_{type_}']


if __name__ == "__main__":
    main()
