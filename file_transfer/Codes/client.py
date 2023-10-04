from socket import *
import json
from os.path import getsize
import hashlib
import argparse
import struct
import time


# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'


def get_username_md5(username):
    password = hashlib.md5(str(username).encode()).hexdigest()
    return password  # the type of password-- str


def get_file_md5(filename):
    """
    Get MD5 value for big file
    :param filename:
    :return:
    """
    m = hashlib.md5()  # hashlib.md5() returns a md5 object (here m is a md5 object)
    with open(filename, 'rb') as fid:
        while True:
            d = fid.read(2048)
            if not d:
                break
            m.update(d)  # m.update(d) means that add another message d to the object m
    return m.hexdigest()  # m.hexdigest() generates the ciphertext in hexadecimal form


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--server_ip", default='127.0.0.1', action='store', required=False, dest="server_ip",
                       help="The IP address binds to the server. Default bind all IP")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listens on. Default is 1379.")
    parse.add_argument("--id", default='1202437', action='store', required=False, dest="id",
                       help="Your ID")
    parse.add_argument("--f", default='', action='store', required=False, dest="file",
                       help="File path. Default is empty (no file will be uploaded)")

    return parse.parse_args()


def make_packet(json_data, bin_data=None):
    """
    Make a packet following the STEP protocol.
    Any information or data for TCP transmission has to use this function to get the packet.
    :param json_data: * json_data-- a dictionary
    :param bin_data: * binary_data-- optional part in STEP Protocol
    :return:
        The complete binary packet
    """
# recall that STEP Protocol defines the format of message: len(JSON_DATA)+len(Binary)+JSONDataPart+BinaryDataPart
# each 32-bit for the first two
# dict() returns a new dict. json.dumps() use ASCII to encode in default. 'ensure_ascii=False' assures some characters
# cannot be encoded by ASCII (such as Chinese) are able to successfully encode
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:  # 'I' means unsigned integer, which is 4-byte(32-bit)
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def make_request_packet(operation, data_type, json_data, bin_data=None):
    """
    Make a packet for response
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param data_type: [FILE, DATA, AUTH]
    :param json_data: * json_data-- a dictionary
    :param bin_data: * binary_data-- optional part in STEP Protocol
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_REQUEST
    json_data[FIELD_TYPE] = data_type
    return make_packet(json_data, bin_data)


def get_tcp_packet(conn):
    """
    Receive a complete TCP "packet" from a TCP stream and get the json data and binary data.
    :param conn: the TCP connection
    :return:
        json_data
        bin_data
    """
    bin_data = b''  # b'': the type is byte data
    while len(bin_data) < 8:  # STEP Protocol: len(JSON_DATA)+len(Binary) occupy first 8 bytes
        data_rec = conn.recv(8)  # in this loop can only receive the first 8 bytes to variable bin_data
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None  # this function aims to return both json and binary data (so here two None)
        bin_data += data_rec
    data = bin_data[:8]
    bin_data = bin_data[8:]  # bin_data[8:] == [], so here bin_data is an empty list
    j_len, b_len = struct.unpack('!II', data)
    while len(bin_data) < j_len:
        data_rec = conn.recv(j_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    j_bin = bin_data[:j_len]

    try:
        json_data = json.loads(j_bin.decode())
    except Exception as ex:
        return None, None

    bin_data = bin_data[j_len:]
    while len(bin_data) < b_len:
        data_rec = conn.recv(b_len)
        if data_rec == b'':
            time.sleep(0.01)
        if data_rec == b'':
            return None, None
        bin_data += data_rec
    return json_data, bin_data


def login_get_token(username, connection_socket):
    password = get_username_md5(username)
    connection_socket.send(make_request_packet(OP_LOGIN, TYPE_AUTH,
                                               {FIELD_USERNAME: username, FIELD_PASSWORD: password}))
    while True:
        json_data, bin_data = get_tcp_packet(connection_socket)
        if json_data[FIELD_OPERATION] == OP_LOGIN and json_data[FIELD_TYPE] == TYPE_AUTH and json_data[FIELD_STATUS] == 200:
            token = json_data[FIELD_TOKEN]
            break
        else:
            connection_socket.send(make_request_packet(OP_LOGIN, TYPE_AUTH,
                                                       {FIELD_USERNAME: username, FIELD_PASSWORD: password}))
            continue

    return token  # here do not need to decode token, later just send this token to server, it will do authentication


def file_delete(connection_socket, token, key, username):
    connection_socket.send(make_request_packet(OP_DELETE, TYPE_FILE,
                                               {FIELD_TOKEN: token, FIELD_KEY: key}))
    while True:
        json_data, bin_data = get_tcp_packet(connection_socket)
        if json_data[FIELD_TYPE] == TYPE_AUTH:  # it means there's sth wrong with the token
            token = login_get_token(username, connection_socket)
            print(f'Token: {token}')
            print(json_data)
            connection_socket.send(make_request_packet(OP_DELETE, TYPE_FILE,
                                                       {FIELD_TOKEN: token, FIELD_KEY: key}))
            continue
        if json_data[FIELD_OPERATION] == OP_GET and json_data[FIELD_TYPE] == TYPE_FILE:
            if json_data[FIELD_STATUS] == 404 or 200:  # key does not exist, no need to delete
                print(json_data)
                return
            if json_data[FIELD_STATUS] == 410:  # field key is missing
                print(json_data)
                connection_socket.send(make_request_packet(OP_DELETE, TYPE_FILE,
                                                           {FIELD_TOKEN: token, FIELD_KEY: key}))
                continue


def get_upload_plan(connection_socket, file_path, token, username):
    plan = {}
    if file_path == '':
        # no file needs to upload
        return plan
    key = file_path.split('/')[-1]
    file_size = getsize(file_path)
    connection_socket.send(make_request_packet(OP_SAVE, TYPE_FILE,
                                               {FIELD_TOKEN: token, FIELD_KEY: key, FIELD_SIZE: file_size}))

    while True:
        json_data, bin_data = get_tcp_packet(connection_socket)
        if json_data[FIELD_TYPE] == TYPE_AUTH:  # it means there's sth wrong with the token
            token = login_get_token(username, connection_socket)
            print(f'Token: {token}')
            print(json_data)
            connection_socket.send(make_request_packet(OP_SAVE, TYPE_FILE,
                                                       {FIELD_TOKEN: token, FIELD_KEY: key, FIELD_SIZE: file_size}))
            continue
        if json_data[FIELD_OPERATION] == OP_SAVE and json_data[FIELD_TYPE] == TYPE_FILE:
            if json_data[FIELD_STATUS] == 402:  # key exists, no need to upload
                print(json_data)
                return None
            if json_data[FIELD_STATUS] == 410:  # field 'size' missing
                print(json_data)
                connection_socket.send(make_request_packet(OP_SAVE, TYPE_FILE,
                                                           {FIELD_TOKEN: token, FIELD_KEY: key, FIELD_SIZE: file_size}))
                continue
            if json_data[FIELD_STATUS] == 200:
                print(json_data)
                plan[FIELD_KEY] = json_data[FIELD_KEY]
                plan[FIELD_TOTAL_BLOCK] = json_data[FIELD_TOTAL_BLOCK]
                plan[FIELD_BLOCK_SIZE] = json_data[FIELD_BLOCK_SIZE]
                plan[FIELD_SIZE] = json_data[FIELD_SIZE]
                return plan


def file_upload(username, connection_socket, file_path, token):
    upload_plan = get_upload_plan(connection_socket, file_path, token, username)
    if upload_plan == {}:
        print('Please indicate the file to be uploaded (no file is uploaded).')
        connection_socket.close()
        return
    if upload_plan is None:
        connection_socket.close()
        return
    key = upload_plan[FIELD_KEY]
    total_block = upload_plan[FIELD_TOTAL_BLOCK]
    block_size = upload_plan[FIELD_BLOCK_SIZE]

    plan = {
        FIELD_TOKEN: token,
        FIELD_KEY: key,
    }
    is_last_block = False
    file_size = getsize(file_path)
    with open(file_path, 'rb') as f:
        for i in range(0, total_block):
            f.seek(i * block_size)
            if block_size * (i + 1) < file_size:
                bin_data_send = f.read(block_size)
            else:
                bin_data_send = f.read(file_size - block_size * i)
                is_last_block = True
            plan.update({FIELD_BLOCK_INDEX: i})
            connection_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, plan, bin_data_send))

            while True:
                if is_last_block:
                    json_data, bin_data_recv = get_tcp_packet(connection_socket)
                    file_md5 = get_file_md5(file_path)
                    if json_data[FIELD_OPERATION] == OP_UPLOAD and json_data[FIELD_TYPE] == TYPE_FILE:
                        if json_data[FIELD_STATUS] == 200:
                            md5_recv = json_data[FIELD_MD5]
                            if file_md5 != md5_recv:
                                file_delete(connection_socket, token, key, username)
                                file_upload(username, connection_socket, file_path, token)
                            else:
                                print(json_data)
                                connection_socket.close()
                                return

                        if json_data[FIELD_STATUS] == 410:  # field missing
                            print(json_data)
                            connection_socket.send(
                                make_request_packet(OP_UPLOAD, TYPE_FILE, plan, bin_data_send))
                            continue
                        if json_data[FIELD_STATUS] == 408:  # key not accepted or key existed-- need optimize
                            print(json_data)
                            connection_socket.close()
                            return
                        if json_data[FIELD_STATUS] == 405:  # block_index exceeds-- delete tmp file? or not?
                            print(json_data)
                            connection_socket.close()
                            return
                        if json_data[FIELD_STATUS] == 406:  # block_file is wrong-- delete tmp file? or not?
                            print(json_data)
                            connection_socket.close()
                            return

                    if json_data[FIELD_TYPE] == TYPE_AUTH:  # it means there's sth wrong with the token
                        token = login_get_token(username, connection_socket)
                        print(f'Token: {token}')
                        print(json_data)
                        connection_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, plan, bin_data_send))
                        continue

                    connection_socket.close()
                    return

                json_data, bin_data_recv = get_tcp_packet(connection_socket)
                if json_data[FIELD_TYPE] == TYPE_AUTH:  # it means there's sth wrong with the token
                    token = login_get_token(username, connection_socket)
                    print(f'Token: {token}')
                    print(json_data)
                    connection_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, plan, bin_data_send))
                    continue

                if json_data[FIELD_OPERATION] == OP_UPLOAD and json_data[FIELD_TYPE] == TYPE_FILE:
                    if json_data[FIELD_STATUS] == 200:
                        print(json_data)
                        break
                    if json_data[FIELD_STATUS] == 410:  # field missing
                        print(json_data)
                        connection_socket.send(make_request_packet(OP_UPLOAD, TYPE_FILE, plan, bin_data_send))
                        continue
                    if json_data[FIELD_STATUS] == 408:  # key not accepted or key existed-- need optimize
                        print(json_data)
                        connection_socket.close()
                        return
                    if json_data[FIELD_STATUS] == 405:  # block_index exceeds-- delete tmp file? or not?
                        print(json_data)
                        connection_socket.close()
                        return
                    if json_data[FIELD_STATUS] == 406:  # block_file is wrong-- delete tmp file? or not?
                        print(json_data)
                        connection_socket.close()
                        return
                connection_socket.close()
                return

    connection_socket.close()


def STEP_upload(username, connection_socket, file_path):
    token = login_get_token(username, connection_socket)  # login first
    print(f'Token: {token}')  # the cw requirement: print token
    file_upload(username, connection_socket, file_path, token)


def tcp_connector(username, server_ip, server_port, file_path):
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    client_socket.connect((server_ip, server_port))
    STEP_upload(username, client_socket, file_path)


def main():
    parser = _argparse()
    server_ip = parser.server_ip
    server_port = parser.port
    username = parser.id
    file_path = parser.file
    tcp_connector(username, server_ip, int(server_port), file_path)


if __name__ == '__main__':
    main()