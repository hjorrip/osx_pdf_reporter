import json

from pylatex import Document
from pylatex.utils import verbatim


def append_plist_to_doc(doc: Document, plist: dict):
    pretty_json = json.dumps(plist, indent=4, sort_keys=True)

    pretty_json_lines = pretty_json.splitlines()
    for line in pretty_json_lines:
        doc.append(verbatim(line))
        doc.append("\n")

def split_long_lines(line: str, char_split: str, max_length: int):

    if len(line) > max_length:

        start_search_idx = max_length - 10
        if start_search_idx > 0:

            insert_at = line.find(char_split, max_length - 10) + 1

            splitted_string = line[:insert_at] + '\n' + line[insert_at:]

            return splitted_string

        else:
            return line
    else:
        return line