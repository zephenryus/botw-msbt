import argparse
import os
import struct

import yaml


class MSBT:
    filename = ''

    data_object = []

    labels = []
    label_header = []
    label_section_size = 0
    label_table_count = 0

    attributes = []

    text_header = []
    text = []

    def __init__(self, path=None):
        if path != None:
            print("Parsing MSBT file...")
            self.read_file(path)

    def read_file(self, path):
        self.filename = os.path.basename(path)
        print("Reading {0}...".format(self.filename))

        with open(path, 'rb') as infile:
            signature = infile.read(0x08)

            if signature != b'MsgStdBn':
                print('\033[31mQuitting: {0} is not a Message Std Binary file\033[0m'.format(self.filename))
                print('\033[31mExpected b\'MsgStdBn\' but saw {0}\033[0m'.format(signature))
                exit(101)

            # read file header
            bom, section_count, filesize = \
                struct.unpack('>H4xH2xI', infile.read(14))

            self.align_pointer(infile)

            data_object = []
            for section in range(section_count):
                data_object.append(self.read_section(infile, filesize))

            self.data_object = self.compile_data(data_object)
            # self.data_object = data_object

    def read_text_section(self, infile, filesize):
        section_signature = infile.read(0x04)

        # It's overkill, but double check the header signature
        if section_signature != b'TXT2':
            print('\033[31mError: Invalid text section header\033[0m'.format(self.filename))
            print('\033[31mExpected b\'TXT2\' but saw {0}\033[0m'.format(section_signature))
            exit(104)

        section_size = struct.unpack('>I', infile.read(4))[0]
        self.align_pointer(infile)
        offset_table_start = infile.tell()
        section_stop = offset_table_start + section_size

        offset_count = struct.unpack('>I', infile.read(4))[0]

        header = []
        for _ in range(offset_count):
            header.append({
                'text_offset': struct.unpack('>I', infile.read(4))[0]
            })

        if infile.tell() != 4 + offset_table_start + offset_count * 4:
            print('offset header error')

        header.append({
            'text_offset': section_stop
        })

        texts = []
        text_string = b''
        for index in range(len(header) - 1):
            infile.seek(offset_table_start + header[index]['text_offset'])

            string_size = header[index + 1]['text_offset'] - header[index]['text_offset']
            # texts.append(infile.read(string_size).decode('UTF-16-BE'))

            # Strings can be read with infile.read(string_size)
            # However, I want to strip carriage returns and other unicode characters
            string_pos = 0
            while string_pos < string_size:
                string_pos += 2
                if infile.tell() + 2 > section_stop:
                    break

                utf_16_bytes = struct.unpack('>2s', infile.read(2))[0]

                # Replace carriage return with a space for text output
                if utf_16_bytes == b'\x00\x0a':
                    utf_16_bytes = b'\x00\x20'

                text_string += utf_16_bytes

            text_string = text_string.rstrip(b'\x00')
            texts.append(text_string.decode('UTF-16-BE'))
            text_string = b''

        return {
            'header': header,
            'texts': texts
        }

    def read_label_section(self, infile):
        section_signature = infile.read(0x04)

        # It's overkill, but double check the header signature
        if section_signature != b'LBL1':
            print('\033[31mError: Invalid label section header\033[0m'.format(self.filename))
            print('\033[31mExpected b\'LBL1\' but saw {0}\033[0m'.format(section_signature))
            exit(102)

        section_size = struct.unpack('>I', infile.read(4))[0]
        self.align_pointer(infile)
        offset_table_start = infile.tell()
        section_stop = offset_table_start + section_size

        offset_count = struct.unpack('>I', infile.read(4))[0]

        header = []
        for _ in range(offset_count):
            string_count, string_offset = struct.unpack('>2I', infile.read(8))
            header.append({
                'string_count': string_count,
                'string_offset': string_offset
            })

        if infile.tell() != 4 + offset_table_start + offset_count * 8:
            print('offset header error')

        labels = []
        for index in range(offset_count):
            string_count = header[index]['string_count']

            infile.seek(header[index]['string_offset'] + 0x30)
            while string_count > 0:
                string_length = struct.unpack('>B', infile.read(1))[0]

                label_string = b''
                for _ in range(string_length):
                    label_string += struct.unpack('>s', infile.read(1))[0]
                label_index = struct.unpack('>I', infile.read(4))[0]

                labels.append({
                    'label': label_string.decode('utf-8'),
                    'index': label_index
                })

                string_count -= 1

        return {
            'header': header,
            'labels': labels
        }

    def read_attribute_section(self, infile):
        section_signature = infile.read(0x04)

        # It's overkill, but double check the header signature
        if section_signature != b'ATR1':
            print('\033[31mError: Invalid attribute section header\033[0m'.format(self.filename))
            print('\033[31mExpected b\'ATR1\' but saw {0}\033[0m'.format(section_signature))
            exit(103)

        section_size = struct.unpack('>I', infile.read(4))[0]

        self.align_pointer(infile)
        offset_table_start = infile.tell()
        section_stop = offset_table_start + section_size

        offset_count = struct.unpack('>2I', infile.read(8))

        header = []
        for _ in range(offset_count):
            header.append({
                'attribute_offset': struct.unpack('>I', infile.read(4))[0]
            })

        attributes = []
        attribute_string = b''
        while True:
            if infile.tell() + 2 > section_stop:
                break

            utf_16_bytes = struct.unpack('>2s', infile.read(2))[0]

            if utf_16_bytes == b'\x00\x00':
                attributes.append(attribute_string.decode('UTF-16-BE'))
                attribute_string = b''
                continue

            attribute_string += utf_16_bytes

        # Remove empty strings from list
        # attributes = [x for x in attributes if x != '']

        return {
            'header': header,
            'attributes': attributes
        }

    def read_section(self, infile, filesize):
        return_data = None

        if infile.tell() + 4 < filesize:
            section_signature = infile.read(4)
            infile.seek(-4, 1)

            if section_signature == b'LBL1':
                return_data = {
                    'labels': self.read_label_section(infile)
                }

            if section_signature == b'ATR1':
                return_data = {
                    'attributes': self.read_attribute_section(infile)
                }

            if section_signature == b'TXT2':
                return_data = {
                    'texts': self.read_text_section(infile, filesize)
                }

            if (16 - infile.tell()) % 16 < filesize:
                self.align_pointer(infile)

        return return_data

    def align_pointer(self, infile):
        realign = (16 - infile.tell()) % 16
        infile.seek(realign, 1)

    def compile_data(self, data_object):
        compiled = {}

        print(data_object[0]['labels']['header'])
        print(data_object[0]['labels']['labels'])
        print(data_object[1]['attributes']['header'])
        print(data_object[1]['attributes']['attributes'])
        print(data_object[2]['texts']['header'])
        print(data_object[2]['texts']['texts'])

        for index in range(len(data_object[0]['labels']['labels'])):
            label = data_object[0]['labels']['labels'][index]
            label_name = label['label']
            label_index = label['index']
            label_text = data_object[2]['texts']['texts'][label_index]

            attributes = data_object[1]['attributes']['attributes'][label_index]

            compiled[label_name] = {
                'text': label_text,
                'attributes': attributes
            }

        return compiled


def main():
    # parser = argparse.ArgumentParser(description="The Legend of Zelda: Breath of the Wild MSBT parser")
    # parser.add_argument("filename", type=str, help="File to be parsed.")

    # args = parser.parse_args()

    # Use for single file
    # msbt = MSBT("C:\\botw-data\\decompressed\\content\\Pack\\Bootup_USen\\Message\\Msg_USen.product\\EventFlowMsg\\100enemy.msbt")
    # save_as_json(msbt.data_object, "C:\\Users\\zephe\\PycharmProjects\\msbt\\output\\json\\100enemy.msbt")

    # Use for directory
    path = "C:\\botw-data\\decompressed\\content\\Pack\\Bootup_USen\\Message\\Msg_USen.product"

    for (dirpath, dirnames, filenames) in os.walk(path):
        directory = dirpath.replace('\\', '/') + '/'

        for filename in filenames:
            print(directory + filename)

            msbt = MSBT(directory + filename)

            output_path = "C:\\Users\\zephe\\PycharmProjects\\msbt\\output\\json\\{0}".format(filename)
            save_as_json(msbt.data_object, output_path)


def save_as_json(data, path):
    import json
    print('Saving {0}.json...'.format(path))
    file = open(path + '.json', 'w')
    file.write(json.dumps(data))
    file.close()


def save_as_yaml(data, path):
    print('Saving {0}.yaml...'.format(path))
    file = open(path + '.yaml', 'w')
    file.write(yaml.dump(data))
    file.close()


if __name__ == "__main__":
    main()
