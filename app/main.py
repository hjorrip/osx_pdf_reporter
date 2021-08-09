from pylatex import Document, NoEscape, NewPage, Package, Command
from modules import system_defences, user_accounts, persistences
from modules.appendix import appendix
from modules.network import network
from modules.processes import processes

if __name__ == '__main__':

    
    geometry_options = {
        "head": "40pt",
        "margin": "0.5in",
        "bottom": "0.6in",
        "includeheadfoot": True
    }

    doc = Document(geometry_options=geometry_options)
    doc.packages.append(Package('seqsplit'))

    data_location = '/output'


    system_defences(doc, data_location)
    user_accounts(doc, data_location)
    persistences(doc, data_location)
    network(doc, data_location)
    processes(doc, data_location)

    doc.generate_pdf(filepath=f"{data_location}/OSX Forensics Report", clean_tex=False)



