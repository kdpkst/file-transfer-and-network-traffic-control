from socket import *
import json
import os
from os.path import join, getsize
import hashlib
import argparse
from threading import Thread
import struct
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import base64
import uuid
import math
import shutil

MAX_PACKET_SIZE = 20480

# Const Value
OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN, OP_ERROR = 'SAVE', 'DELETE', 'GET', 'UPLOAD', 'DOWNLOAD', 'BYE', 'LOGIN', "ERROR"
TYPE_FILE, TYPE_DATA, TYPE_AUTH, DIR_EARTH = 'FILE', 'DATA', 'AUTH', 'EARTH'
FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE, FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOKEN = 'operation', 'direction', 'type', 'username', 'password', 'token'
FIELD_KEY, FIELD_SIZE, FIELD_TOTAL_BLOCK, FIELD_MD5, FIELD_BLOCK_SIZE = 'key', 'size', 'total_block', 'md5', 'block_size'
FIELD_STATUS, FIELD_STATUS_MSG, FIELD_BLOCK_INDEX = 'status', 'status_msg', 'block_index'
DIR_REQUEST, DIR_RESPONSE = 'REQUEST', 'RESPONSE'

logger = logging.getLogger('')


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


def get_time_based_filename(ext, prefix='', t=None):
    """
    Get a filename based on time
    :param ext: ext name of the filename
    :param prefix: prefix of the filename
    :param t: the specified time if necessary, the default is the current time. Unix timestamp
    :return:
    """
    ext = ext.replace('.', '')
    if t is None:
        t = time.time()  # time.time() return the current timestamp
    if t > 4102464500:  # this number = 130 years (2100 year)
        t = t / 1000
    return time.strftime(f"{prefix}%Y%m%d%H%M%S." + ext, time.localtime(t))
        # function time.strftime() requires two argument
        # transform the file name to the format of "prefixtime.ext"


# root logger is the ancestor of all logger.
# handler is used to help logger manage the logs (output info to file or output to screen)
def set_logger(logger_name):
    """
    Create a logger
    :param logger_name: 日志名称
    :return: logger
    """
    logger_ = logging.getLogger(logger_name)  # root logger is returned if no name is specified
    logger_.setLevel(logging.INFO)  # INFO: only output log that the level higher than INFO
                                    # the default level is WARNING
    formatter = logging.Formatter(
        '\033[0;34m%s\033[0m' % '%(asctime)s-%(name)s[%(levelname)s] %(message)s @ %(filename)s[%(lineno)d]',
        datefmt='%Y-%m-%d %H:%M:%S')
    # '\033[0;34m%s\033[0m' % is just a code to set font color
    # Formatter specifies the output format of the log
    # 'datefmt='%Y-%m-%d %H:%M:%S' specifies the time format of '%(asctime)s'

    # --> LOG FILE
    logger_file_name = get_time_based_filename('log')
    os.makedirs(f'log/{logger_name}', exist_ok=True)  # os.makedirs() can create directory recursively
                                                      # set param exist_ok=True, assuring the directory will not be created if it already exists
    # TimedRotatingFileHandler() creates log at a fixed interval
    # param-- filename:prefixname, when:'D' means Days, interval:create log after how many 'when', backupCount:the number of logs reserved
    fh = TimedRotatingFileHandler(filename=f'log/{logger_name}/{logger_file_name}', when='D', interval=1, backupCount=1)
    fh.setFormatter(formatter)

    fh.setLevel(logging.INFO)

    # --> SCREEN DISPLAY
    ch = logging.StreamHandler()  # output log to specified stream, the default param is sys.stderr (here just output to screen)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    logger_.propagate = False  # it indicates that do not send log upstream
    logger_.addHandler(ch)
    logger_.addHandler(fh)
    return logger_


def _argparse():
    parse = argparse.ArgumentParser()
    parse.add_argument("--ip", default='', action='store', required=False, dest="ip",
                       help="The IP address binds to the server. Default bind all IP.")
    parse.add_argument("--port", default='1379', action='store', required=False, dest="port",
                       help="The port that server listens on. Default is 1379.")
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


def make_response_packet(operation, status_code, data_type, status_msg, json_data, bin_data=None):
    """
    Make a packet for response
    :param operation: [SAVE, DELETE, GET, UPLOAD, DOWNLOAD, BYE, LOGIN]
    :param status_code: 200 or 400+
    :param data_type: [FILE, DATA, AUTH]
    :param status_msg: A human-readable status massage
    :param json_data: * json_data-- a dictionary
    :param bin_data: * binary_data-- optional part in STEP Protocol
    :return:
    """
    json_data[FIELD_OPERATION] = operation
    json_data[FIELD_DIRECTION] = DIR_RESPONSE
    json_data[FIELD_STATUS] = status_code
    json_data[FIELD_STATUS_MSG] = status_msg
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
            return None, None  # !!!(...) maybe a bug-- should be return json_data, None
        bin_data += data_rec
    return json_data, bin_data


def data_process(username, request_operation, json_data, connection_socket):
    """
    Data Process
    :param username:
    :param request_operation: * for data process: the operation only contains GET, SAVE, DELETE
    :param json_data: * a dictionary, maybe get from function get_tcp_packet(conn)
    :param connection_socket:
    :return: None
    """
    global logger
    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys():  # STEP Protocol defines: get the data using the key
            logger.info(f'<-- Get data without key.')
            logger.error(f'<-- Field "key" is missing for DATA GET.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_DATA, f'Field "key" is missing for DATA GET.', {}))
            # 410: field is missing
            return
        logger.info(f'--> Get data {json_data[FIELD_KEY]}')
        # if this path does not exist, then no data can be transferred back to client
        # os.path.exists() checks whether indicated file exists or nor-- return True or False
        # join() comes from os.path-- used to concatenate file path
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False:
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_DATA, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            # 404: cannot find the key
            return
        try:
            with open(join('data', username, json_data[FIELD_KEY]), 'r') as fid:
                data_from_file = json.load(fid)  # json.load(file)-- read JSON_data in file and transform to python type
                logger.info(f'<-- Find the data and return to client.')
                connection_socket.send(
                    make_response_packet(OP_GET, 200, TYPE_DATA, f'OK', data_from_file))  # 200: successful
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')  #

    if request_operation == OP_SAVE:
    # uuid-- Universally Unique Identifier (128-bit): generate unique ID using MAC address, timestamp, random number...
    # uuid.uuid4()-- uuid4 module generate uuid based on random number
        key = str(uuid.uuid4())  # STEP Protocol defines: server reply with a random key if client does not indicate one
        if FIELD_KEY in json_data.keys():
            key = json_data[FIELD_KEY]
        logger.info(f'--> Save data with key "{key}"')
        if os.path.exists(join('data', username, key)) is True:
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_DATA, f'This key "{key}" is existing.', {}))
            # 402: the key is existing
            return
        try:
            with open(join('data', username, key), 'w') as fid:
                # json.dump(JSON_data, file) transform python type to JSON data type, then write it into file
                json.dump(json_data, fid)
                logger.error(f'<-- Data is saved with key "{key}"')
                connection_socket.send(
                    make_response_packet(OP_SAVE, 200, TYPE_DATA, f'Data is saved with key "{key}"', {FIELD_KEY: key}))
                # STEP Protocol defines: server will reply with the key
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')  # search...

    if request_operation == OP_DELETE:  # STEP Protocol defines: delete the data using the key
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Delete data without any key.')
            logger.error(f'<-- Field "key" is missing for DATA delete.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 410, TYPE_DATA, f'Field "key" is missing for DATA delete.', {}))
            return
        if os.path.exists(join('data', username, json_data[FIELD_KEY])) is False:  # nothing to delete if key does not exist
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 404, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is not existing.',
                                     {}))
            return
        try:
            os.remove(join('data', username, json_data[FIELD_KEY]))  # os.remove(path)-- used to delete only file
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            connection_socket.send(
                make_response_packet(OP_DELETE, 200, TYPE_DATA, f'The "key" {json_data[FIELD_KEY]} is deleted.',
                                     {FIELD_KEY: json_data[FIELD_KEY]}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')


def file_process(username, request_operation, json_data, bin_data, connection_socket):
    """
    File Process
    :param username:
    :param request_operation:
    :param json_data:
    :param bin_data:
    :param connection_socket:
    :return:
    """
    global logger
    # GET operation is to start a download request. Server will just reply the download plan rather than files
    if request_operation == OP_GET:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Plan to download file')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for DATA GET.', {}))
            return
        logger.info(f'--> Plan to download file with "key" {json_data[FIELD_KEY]}')
        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is False:  # tmp-- temp file (see operation download below)
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The key {json_data[FIELD_KEY]} is not existing.', {}))
            return

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False and os.path.exists(
                join('tmp', username, json_data[FIELD_KEY])) is True:  # refer to operation download below
            logger.error(f'<-- The key {json_data[FIELD_KEY]} is not completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE,
                                     f'The key {json_data[FIELD_KEY]} is not completely uploaded.', {}))
            return

        file_path = join('file', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)  # getsize(file_path) comes from os.path-- gain the indicated file size in byte
        block_size = MAX_PACKET_SIZE  # it is a pre-defined variable (line 17)
        total_block = math.ceil(file_size / block_size)
        md5 = get_file_md5(file_path)
        # Download Plan
        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_SIZE: file_size,
            FIELD_TOTAL_BLOCK: total_block,
            FIELD_BLOCK_SIZE: block_size,
            FIELD_MD5: md5
        }
        logger.info(f'<-- Plan: file size {file_size}, total block number {total_block}.')
        # !!! bug-- should be total_block
        connection_socket.send(
            make_response_packet(OP_GET, 200, TYPE_FILE, f'OK. This is the download plan.', rval))
        return

    if request_operation == OP_SAVE:  # STEP Protocol defines: SAVE requires field 'key' and 'size' in json_data
        key = str(uuid.uuid4())       # and the server will only reply with the file upload plan and write a tmp file
        if FIELD_KEY in json_data.keys():
            key = json_data[FIELD_KEY]
        logger.info(f'--> Plan to save/upload a file with key "{key}"')
        if os.path.exists(join('file', username, key)) is True:
            logger.error(f'<-- This key "{key}" is existing.')
            connection_socket.send(make_response_packet(OP_SAVE, 402, TYPE_FILE, f'This "key" {key} is existing.', {}))
            return
        if FIELD_SIZE not in json_data.keys():
            logger.error(f'<-- This file "size" has to be included.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 410, TYPE_FILE, f'This file "size" has to be included', {}))
            return
        file_size = json_data[FIELD_SIZE]
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        try:
            rval = {
                FIELD_KEY: key,
                FIELD_SIZE: file_size,
                FIELD_TOTAL_BLOCK: total_block,
                FIELD_BLOCK_SIZE: block_size,
            }
            # Write a tmp file
            with open(join('tmp', username, key), 'wb+') as fid:  # wb+: open the file in r and b mode of binary
                fid.seek(file_size - 1)  # here is for later UPLOAD to easily get file size (about line 439)
                fid.write(b'\0')  # \0 is an empty character

            fid = open(join('tmp', username, key + '.log'), 'w')
            fid.close()  # create file named key.log, than do nothing and close it

            logger.error(f'<-- Upload plan: key {key}, total block number {total_block}, block size {block_size}.')
            connection_socket.send(
                make_response_packet(OP_SAVE, 200, TYPE_FILE, f'This is the upload plan.', rval))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')

    if request_operation == OP_DELETE:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Delete file without any key.')
            logger.error(f'<-- Field "key" is missing for FILE delete.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE delete.', {}))
            return

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False:
            if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is True:
                try:
                    os.remove(join('tmp', username, json_data[FIELD_KEY]))
                    os.remove(join('tmp', username, json_data[FIELD_KEY]) + '.log')
                except Exception as ex:
                    logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')
                logger.error(
                    f'<-- The "key" {json_data[FIELD_KEY]} is not completely uploaded. The tmp files are deleted.')
                connection_socket.send(
                    make_response_packet(OP_GET, 404, TYPE_FILE,
                                         f'The "key" {json_data[FIELD_KEY]} is not completely uploaded. '
                                         f'The tmp files are deleted.',
                                         {}))
                return
            # here means to deal with the situation that both file and tmp do not exist (no need to remove)
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is not existing.', {}))
            return
        try:
            os.remove(join('file', username, json_data[FIELD_KEY]))
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is deleted.')
            connection_socket.send(
                make_response_packet(OP_GET, 200, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is deleted.',
                                     {FIELD_KEY: json_data[FIELD_KEY]}))
        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')

    if request_operation == OP_UPLOAD:
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Upload file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'Field "key" is missing for FILE uploading.', {}))
            return
        logger.info(f'--> Upload file/block of "key" {json_data[FIELD_KEY]}.')

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is True:
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is completely uploaded.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is completely uploaded.', {}))
            return                      # !!! feels like 402 also validates

        if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is False:
            logger.error(
                f'<-- The "key" {json_data[FIELD_KEY]} is not accepted for uploading.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 408, TYPE_FILE,
                                     f'The "key" {json_data[FIELD_KEY]} is not accepted for uploading.',
                                     {}))
            return
        # STEP Protocol defines: upload a file block or the whole file using "key" and "block_index"
        if FIELD_BLOCK_INDEX not in json_data.keys():
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('tmp', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 405, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            # !!! maybe bug here-- 410 seems not appropriate
            return
        # classification: last block or non-last block
        if block_index == total_block - 1 and len(bin_data) != file_size - block_size * block_index:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        if block_index != total_block - 1 and len(bin_data) != block_size:
            logger.error(f'<-- The "block_size" is wrong.')
            connection_socket.send(
                make_response_packet(OP_UPLOAD, 406, TYPE_FILE, f'The "block_size" is wrong.', {}))
            return
        # STEP Protocol is TCP-based. Thus, no need to consider out-of-order in default
        # so fid.seek(block_size * block_index) assures in-order file data if nothing goes wrong
        with open(file_path, 'rb+') as fid:
            fid.seek(block_size * block_index)
            fid.write(bin_data)
        with open(file_path + '.log', 'a') as fid:  # note the mode is 'a' (append rather cover)
            fid.write(f'{block_index}\n')  # note here has '\n'-- every line has one block index
        fid = open(file_path + '.log', 'r')
        lines = fid.readlines()  # readlines() returns a list containing content of each line in the file
        fid.close()
        rval = {
            FIELD_KEY: json_data[FIELD_KEY],
            FIELD_BLOCK_INDEX: block_index
        }

        if len(set(lines)) == total_block:  # set() creates a set (no duplicate element)
            md5 = get_file_md5(file_path)
            rval[FIELD_MD5] = md5  # STEP Protocol defines: server also replies with md5 value
            os.remove(file_path + '.log')
            # shutil.move(source_path, destination_path) used to move file-- almost same effect as Linux mv command
            shutil.move(file_path, join('file', username, json_data[FIELD_KEY]))

        connection_socket.send(
            make_response_packet(OP_UPLOAD, 200, TYPE_FILE, f'The block {block_index} is uploaded.', rval))
        return

    if request_operation == OP_DOWNLOAD:  # !!! maybe bug-- replace OP_GET with OP_DOWNLOAD
        if FIELD_KEY not in json_data.keys():
            logger.info(f'--> Download file/block without any key.')
            logger.error(f'<-- Field "key" is missing for FILE block downloading.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'Field "key" is missing for FILE downloading.', {}))
            return
        logger.info(f'--> Download file/block of "key" {json_data[FIELD_KEY]}.')

        if os.path.exists(join('file', username, json_data[FIELD_KEY])) is False:
            if os.path.exists(join('tmp', username, json_data[FIELD_KEY])) is True:
                logger.error(
                    f'<-- The "key" {json_data[FIELD_KEY]} is not completely uploaded. Please upload it first.')
                connection_socket.send(
                    make_response_packet(OP_GET, 404, TYPE_FILE,
                                         f'The "key" {json_data[FIELD_KEY]} is not completely uploaded. '
                                         f'Please upload it first',
                                         {}))
                return
            logger.error(f'<-- The "key" {json_data[FIELD_KEY]} is not existing.')
            connection_socket.send(
                make_response_packet(OP_GET, 404, TYPE_FILE, f'The "key" {json_data[FIELD_KEY]} is not existing.', {}))
            return
        # STEP Protocol defines: download a file block or the whole file using "key" and "block_index"
        if FIELD_BLOCK_INDEX not in json_data.keys():
            logger.error(f'<-- The "block_index" is compulsory.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" is compulsory.', {}))
            return
        file_path = join('file', username, json_data[FIELD_KEY])
        file_size = getsize(file_path)
        block_size = MAX_PACKET_SIZE
        total_block = math.ceil(file_size / block_size)
        block_index = json_data[FIELD_BLOCK_INDEX]
        if block_index >= total_block:
            logger.error(f'<-- The "block_index" exceed the max index.')
            connection_socket.send(
                make_response_packet(OP_GET, 405, TYPE_FILE, f'The "block_index" exceed the max index.', {}))
            return
        if block_index < 0:
            logger.error(f'<-- The "block_index" should >= 0.')
            connection_socket.send(
                make_response_packet(OP_GET, 410, TYPE_FILE, f'The "block_index" should >= 0.', {}))
            return

        with open(file_path, 'rb') as fid:
            fid.seek(block_size * block_index)
            if block_size * (block_index + 1) < file_size:  # it means if this is not the last file block
                bin_data = fid.read(block_size)
            else:  # it is the last file block
                bin_data = fid.read(file_size - block_size * block_index)

            rval = {
                FIELD_BLOCK_INDEX: block_index,
                FIELD_KEY: json_data[FIELD_KEY],
                FIELD_SIZE: len(bin_data)
            }
            logger.info(f'<-- Return block {block_index}({len(bin_data)}bytes) of "key" {json_data[FIELD_KEY]} >= 0.')

            connection_socket.send(make_response_packet(OP_DOWNLOAD, 200, TYPE_FILE,
                                                        'An available block.', rval, bin_data))


def STEP_service(connection_socket, addr):
    """
    STEP Protocol service
    :param connection_socket:
    :param addr:
    :return: None
    """
    global logger
    data = None
    while True:
        json_data, bin_data = get_tcp_packet(connection_socket)
        json_data: dict
        if json_data is None:
            logger.warning('Connection is closed by client.')
            break

        # ACK for "Three Body". If you never read the book "Three Body",
        # just understand the following part as an Echo function. This part is out of the protocol.
        # This is an Easter egg. Aha, this is a very good book.
        if FIELD_DIRECTION in json_data:
            if json_data[FIELD_DIRECTION] == DIR_EARTH:
                connection_socket.send(
                    make_response_packet('3BODY', 333, 'DANGEROUS', f'DO NOT ANSWER! DO NOT ANSWER! DO NOT ANSWER!', {}))
                continue

        # Check the compulsory fields
        compulsory_fields = [FIELD_OPERATION, FIELD_DIRECTION, FIELD_TYPE]

        check_ok = True
        for _compulsory_fields in compulsory_fields:
            if _compulsory_fields not in list(json_data.keys()):
                connection_socket.send(
                    make_response_packet(OP_ERROR, 400, 'ERROR', f'Compulsory field {_compulsory_fields} is missing.',
                                         {}))
                check_ok = False
                break
        if check_ok is False:
            continue

        request_type = json_data[FIELD_TYPE]
        request_operation = json_data[FIELD_OPERATION]
        request_direction = json_data[FIELD_DIRECTION]
        # it seems like client can only use type 'REQUEST'
        if request_direction != DIR_REQUEST:
            connection_socket.send(
                make_response_packet(OP_ERROR, 407, 'ERROR', f'Wrong direction. Should be "REQUEST"', {}))
            continue

        if request_operation not in [OP_SAVE, OP_DELETE, OP_GET, OP_UPLOAD, OP_DOWNLOAD, OP_BYE, OP_LOGIN]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 408, 'ERROR', f'Operation {request_operation} is not allowed', {}))
            continue

        if request_type not in [TYPE_FILE, TYPE_DATA, TYPE_AUTH]:
            connection_socket.send(
                make_response_packet(OP_ERROR, 409, 'ERROR', f'Type {request_type} is not allowed', {}))
            continue
        # login request from client (login first and then do other operations)
        # username and password must be included
        if request_operation == OP_LOGIN:
            if request_type != TYPE_AUTH:
                connection_socket.send(
                    make_response_packet(OP_LOGIN, 409, TYPE_AUTH, f'Type of LOGIN has to be AUTH.', {}))
                continue
            else:
                if FIELD_USERNAME not in json_data.keys():
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"username" has to be a field for LOGIN', {}))
                    continue
                if FIELD_PASSWORD not in json_data.keys():
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 410, TYPE_AUTH, f'"password" has to be a field for LOGIN', {}))
                    continue
                # STEP Protocol defines: username-- student_id and password-- md5(student_id)
                # Check the username and password
                if hashlib.md5(json_data[FIELD_USERNAME].encode()).hexdigest().lower() != json_data['password'].lower():
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 401, TYPE_AUTH, f'"Password error for login.', {}))
                    continue
                else:
                    # Login successful
                    user_str = f'{json_data[FIELD_USERNAME].replace(".", "_")}.' \
                               f'{get_time_based_filename("login")}'
                    md5_auth_str = hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest()
                    connection_socket.send(
                        make_response_packet(OP_LOGIN, 200, TYPE_AUTH, f'Login successfully', {
                            FIELD_TOKEN: base64.b64encode(f'{user_str}.{md5_auth_str}'.encode()).decode()
                        }))  # base64.b64encode(byte) and base64.b64decode() are for encoding and decoding strings
                    # base64.b64encode() returns byte-type
                    continue

        # If the operation is not LOGIN, check token
        if FIELD_TOKEN not in json_data.keys():
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'No token.', {}))
            continue

        token = json_data[FIELD_TOKEN]
        token = base64.b64decode(token).decode()  # base64.b64decode() returns byte-type. here decode() to str-type
        token: str
        # {user_str}.{md5_auth_str}-- the correct format must contain 4 dots (username.time.login.md5_auth_str)
        if len(token.split('.')) != 4:
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'Token format is wrong.', {}))
            continue

        user_str = ".".join(token.split('.')[:3])
        md5_auth_str = token.split('.')[3]
        if hashlib.md5(f'{user_str}kjh20)*(1'.encode()).hexdigest().lower() != md5_auth_str.lower():
            connection_socket.send(
                make_response_packet(request_operation, 403, TYPE_AUTH, f'Token is wrong.', {}))
            continue

        username = token.split('.')[0]

        os.makedirs(join('data', username), exist_ok=True)
        os.makedirs(join('file', username), exist_ok=True)
        os.makedirs(join('tmp', username), exist_ok=True)

        if request_type == TYPE_DATA:
            data_process(username, request_operation, json_data, connection_socket)
            continue

        if request_type == TYPE_FILE:
            file_process(username, request_operation, json_data, bin_data, connection_socket)
            continue

    connection_socket.close()
    logger.info(f'Connection close. {addr}')


def tcp_listener(server_ip, server_port):
    """
    TCP listener: listen to a port and assign TCP sub connections using new threads
    :param server_ip
    :param server_port
    :return: None
    """
    global logger
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # setsockopt() is an extension for socket(), providing more options/parameters to select
    # SOL_SOCKET, SO_REUSEADDR means that allow reuse of local addresses and ports
    server_socket.bind((server_ip, int(server_port)))
    server_socket.listen(20)
    logger.info(
        f'Start the TCP service, listing {server_port} on IP {"All available" if server_ip == "" else server_ip}')
    while True:
        try:
            connection_socket, addr = server_socket.accept()
            logger.info(f'--> New connection from {addr[0]} on {addr[1]}')
            th = Thread(target=STEP_service, args=(connection_socket, addr))
            # this means set thread "step_service" as daemon
            # thread "step_service" will exit as the main thread exits
            th.daemon = True
            th.start()

        except Exception as ex:
            logger.error(f'{str(ex)}@{ex.__traceback__.tb_lineno}')


def main():
    global logger
    logger = set_logger('STEP')
    parser = _argparse()
    server_ip = parser.ip
    server_port = parser.port

    os.makedirs('data', exist_ok=True)
    os.makedirs('file', exist_ok=True)

    tcp_listener(server_ip, server_port)


if __name__ == '__main__':
    main()
