import socket
import os
import io
import argparse
import hashlib
import getpass
import tempfile
from _lzma import LZMAError

import py7zr


def get_file_paths(files):
    to_return = {}
    need_compression = len(files) > 1
    for file in files:
        if os.path.exists(file):
            to_return[file] = [os.path.split(file)[1], os.path.join('d4ft', os.path.split(file)[1])]
            if os.path.isdir(file):
                need_compression = True
        else:
            return None, None
    return to_return, need_compression

def parse_address(address, default_address):
    parts = address.split(':')
    if len(parts) == 1:
        if parts[0].isdigit():
            return default_address, int(parts[0])
        else:
            return parts[0], 2581
    else:
        return parts[0], int(parts[1])

def gen_handshake(args):
    if 't' in args.mode:
        if args.password:
            return b'D4FTU'
        else:
            return b'D4FTT'
    else:
        if args.password:
            return b'D4FTC'
        elif args.compress:
            return b'D4FTB'
        else:
            return b'D4FTA'

parser = argparse.ArgumentParser(description='Send or receive a file to/from another console ' +
                                             'running this script.')
parser.add_argument('-c', '--compress', action='store_true',
                    help='Compresses the file(s) before sending. Assumed true if using password ' +
                         'encryption or sending multiple files or a folder. Has no effect in text' +
                         'mode.')
parser.add_argument('-p', '--password', action='store_true',
                    help='Use password encryption on the sent file(s). Sets compression to true.')
parser.add_argument('-H', '--print-hash', action='store_true', dest='hash',
                    help='Print the SHA-256 hash of the sent or received file.')
parser.add_argument('-n', '--no-progress-bar', action='store_false', dest='bar',
                    help='Disables the progress bar.')
parser.add_argument('-a', '-d', '-b', '--address', default='2581', dest='address',
                    help='The destination or bind address and/or port, default ' +
                         '\'127.0.0.1:2581\' in send mode, \'0.0.0.0:2581\' in receive mode')
parser.add_argument('-r', '--reverse', action='store_true',
                    help='Run in reverse mode (sender listens).')
parser.add_argument('mode', choices=['s', 'st', 'r'],
                    help='Sets the mode of operation, options are: ' +
                         '{}.'.format(['s', 'st', 'r']))
parser.add_argument('files', nargs=argparse.REMAINDER,
                    help='The file(s) or text to send, if in send mode. Multiple files or a ' +
                         'folder sets compression to true.')

args = parser.parse_args()

if args.mode[0] == 's':
    bind_addr = parse_address(args.address, '0.0.0.0' if args.reverse else '127.0.0.1')
    if len(args.files) == 0:
        if args.mode == 'st':
            parser.error('Please provide some text.')
        else:
            parser.error('Please specify at least one file or folder.')
    if args.mode == 'st':
        if args.password:
            password = getpass.getpass()
            file_obj = io.BytesIO()
            fd, tempfile_name = tempfile.mkstemp(text=True)
            with os.fdopen(fd, 'w') as f:
                f.write(' '.join(args.files))
            print('Encrypting...')
            with py7zr.SevenZipFile(file_obj, 'w', password=password) as archive:
                archive.write(tempfile_name, 'd4ft.txt')
                os.remove(tempfile_name)
            file_obj.seek(0)
            file_data = file_obj.read()
        else:
            file_data = bytes(' '.join(args.files), 'utf8')
        try:
            file_length = len(file_data).to_bytes(4, 'big')
        except OverflowError:
            parser.error('The text given is too long.')
    else:
        files, need_compression = get_file_paths(args.files)
        if files is None:
            parser.error('One or more of the provided files does not exist')
        if args.password or need_compression:
            args.compress = True
        if args.compress:
            if args.password:
                password = getpass.getpass()
            else:
                password = None
            file_obj = io.BytesIO()
            print('Compressing...')
            with py7zr.SevenZipFile(file_obj, 'w', password=password,
                                       header_encryption=args.password) as archive:
                for file in files.keys():
                    if os.path.isdir(file):
                        archive.writeall(file, files[file][0])
                    else:
                        archive.write(file, files[file][0])
            file_obj.seek(0)
            file_data = file_obj.read()
        else:
            with open(args.files[0], 'rb') as f:
                file_data = f.read()
        try:
            file_length = len(file_data).to_bytes(4, 'big')
        except OverflowError:
            parser.error('The file specified is too big.')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if args.reverse:
            s.bind(bind_addr)
            s.listen()
            print('Listening...')
            conn, addr = s.accept()
        else:
            s.connect(bind_addr)
            conn = s
        print('Connected')
        while True:
            handshake = gen_handshake(args) + file_length
            hash_obj = hashlib.sha256(file_data)
            handshake += hash_obj.digest()
            if args.hash:
                print('Sent hash: ' + hash_obj.hexdigest())
            if not args.compress and args.mode != 'st':
                handshake += bytes(files[args.files[0]][0], 'utf8')
            conn.send(handshake)
            data = conn.recv(1024)
            if data == b'D4FT' + handshake[4:5].lower():
                print('Handshake complete')
            else:
                parser.error('Failed to handshake')
            cursor = 0
            while cursor < len(file_data):
                chunk = conn.send(file_data[cursor:cursor + 524288])
                cursor += chunk
            conn.sendall(b'D4FTDONE')
            data = conn.recv(1024)
            if data == b'D4FTR':
                conn.sendall(data)
                break
            else:
                print('Transfer failed, retrying...')
        print('Done!')
else:
    bind_addr = parse_address(args.address, '127.0.0.1' if args.reverse else '0.0.0.0')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if args.reverse:
            s.connect(bind_addr)
            conn = s
        else:
            s.bind(bind_addr)
            s.listen()
            print('Listening...')
            conn, addr = s.accept()
        print('Connected')
        while True:
            data = conn.recv(1024)
            info = {
                'mode': str(data[4:5], 'ascii'),
                'length': int.from_bytes(data[5:9], 'big'),
                'hash': data[9:41]
            }
            if info['mode'] == 'A':
                info['filename'] = str(data[41:], 'utf8')
            if args.hash:
                print('Received hash: ' + info['hash'].hex())
            conn.send(b'D4FT' + data[4:5].lower())
            print('Handshake response sent')
            file_data = b''
            while True:
                chunk = conn.recv(524288)
                if chunk[-8:] == b'D4FTDONE':
                    file_data += chunk[:-8]
                    break
                else:
                    file_data += chunk
            if len(file_data) == info['length'] and\
                    hashlib.sha256(file_data).digest() == info['hash']:
                conn.send(b'D4FTR')
                conn.recv(1024)
                break
            else:
                conn.send(b'D4FTS')
                print('Transfer failed, retrying...')
        # TODO: replace this with a user confirmation
        if info['mode'] == 'A':
            print('File transfer complete. Saving as \'{}\'.'.format(info['filename']))
            with open(info['filename'], 'wb') as f:
                f.write(file_data)
            print('Done!')
        elif info['mode'] == 'B':
            print('Compressed file(s) received, decompressing...')
            with py7zr.SevenZipFile(io.BytesIO(file_data), 'r') as archive:
                archive.extractall()
            print('Done!')
        elif info['mode'] == 'C':
            print('Encrypted file(s) received.')
            while True:
                password = getpass.getpass()
                print('Decompressing...')
                try:
                    with py7zr.SevenZipFile(io.BytesIO(file_data), 'r', password=password) as archive:
                        archive.extractall()
                        break
                except LZMAError:
                    print('Incorrect password.')
            print('Done!')
        elif info['mode'] == 'T':
            print('Text received:')
            print(str(file_data, 'utf8'))
        elif info['mode'] == 'U':
            print('Encrypted text received.')
            while True:
                password = getpass.getpass()
                try:
                    with py7zr.SevenZipFile(io.BytesIO(file_data), 'r', password=password) as archive:
                        text_file = archive.read('d4ft.txt')['d4ft.txt']
                    break
                except LZMAError:
                    print('Incorrect password.')
            print('Received text:')
            print(str(text_file.read(), 'utf8'))