import json

from pylatex import Document
from pylatex.utils import verbatim


def append_plist_to_doc(doc: Document, plist: dict):
    pretty_json = json.dumps(plist, indent=4, sort_keys=True)

    pretty_json_lines = pretty_json.splitlines()
    for line in pretty_json_lines:
        doc.append(verbatim(line))
        doc.append("\n")
