import json

from pylatex import Document
from pylatex.utils import verbatim, NoEscape


def append_plist_to_doc(doc: Document, plist: dict):
    pretty_json = json.dumps(plist, indent=4, sort_keys=True)

    pretty_json_lines = pretty_json.splitlines()
    for line in pretty_json_lines:
        doc.append(verbatim(line))
        doc.append("\n")

def split_long_lines(line: str, char_split: str, allowed_line_length: int):

    split_strings = [line[index: index + allowed_line_length] for index in range(0, len(line), allowed_line_length)]

    return '\n'.join(split_strings)

   #while line_length > allowed_line_length:



def line_wrapper(string: str):

    new_string = string

    new_string = str(new_string).replace(r'&', r'\&')
    new_string = str(new_string).replace(r'%', r'\%')
    new_string = str(new_string).replace(r'$', r'\$')
    new_string = str(new_string).replace(r'#', r'\#')
    new_string = str(new_string).replace(r'_', r'\_')
    new_string = str(new_string).replace(r'{', r'\{')
    new_string = str(new_string).replace(r'}', r'\}')
    new_string = str(new_string).replace(r'~', r'\~')
    new_string = str(new_string).replace(r'^', r'\^')
    new_string = str(new_string).replace(r'\\', r'\\\\')

    seqsplit = r'\seqsplit{' + new_string + '}'

    return NoEscape(seqsplit)



