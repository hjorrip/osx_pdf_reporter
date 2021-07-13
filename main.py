from pylatex import Document
from modules import system_defences, user_accounts

if __name__ == '__main__':
    
    geometry_options = {
        "head": "40pt",
        "margin": "0.5in",
        "bottom": "0.6in",
        "includeheadfoot": True
    }

    doc = Document(geometry_options=geometry_options)

    data_location = '../osx_investigator/output'

    system_defences(doc, data_location)
    user_accounts(doc, data_location)


    doc.generate_pdf('This is pdf', clean_tex=False)





