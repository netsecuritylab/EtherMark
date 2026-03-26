import sys, locale

def get_output_encoding():
    enc = sys.stdout.encoding
    if enc is None:
        enc = locale.getpreferredencoding(False)
    return enc

############################################
# GENERAL USE CONSTANTS
############################################

LABELLED_PCAP_SUFFIX = ".labelled"
STR_CMD_SUCCESS = '✔' if get_output_encoding() == 'utf-8' else '+'
STR_CMD_ERROR   = '✖' if get_output_encoding() == 'utf-8' else 'x'
STR_PREFIX      = "[+]"

############################################


LABEL_BYTES_PREFIX = bytes([0xF2, 0xFF])