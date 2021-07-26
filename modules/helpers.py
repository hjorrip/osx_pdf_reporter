import json

from pylatex import Document
from pylatex.utils import verbatim


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







   #if line_length > allowed_line_length:

   #    start_search_idx = allowed_line_length - 10

   #    while line_length > allowed_line_length:

   #        if start_search_idx > 0:

   #            insert_at = line.find(char_split, allowed_line_length - 10) + 1
   #            if insert_at != 0:
   #                splitted_string = line[:insert_at] + '\n' + line[insert_at:]

   #                return splitted_string
   #            else:
   #                return line

   #        else:
   #            return line
   #else:
   #    return line