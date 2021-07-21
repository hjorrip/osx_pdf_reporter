import json
from pylatex import *
from pylatex.utils import *
from modules.helpers import append_plist_to_doc, split_long_lines


def processes(doc: Document, data_location: str):

    doc.append(NewPage())

    with open(f'{data_location}/processes/processes.json') as json_file:
        data_dict = json.load(json_file)

    with doc.create(Section('Processes')):
        doc.append("Collection of process data that may reveal important information. No conclusion can be "
                   "automatically drawn from this information, so it is up to the analyst to find anomalies "
                   "in these datasets.")

        running_applications_subsection(doc, data_dict)

        #TODO: Parsing launchctl_list - but a lot of it are com.apple.... so we can check the code signature
        # for all of those, and exlude them if they check out (and those files that they say are from apple
        # are indeed from apple)


def running_applications_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Running Applications')):
        doc.append("Shows the application list and information about each running application. Bash command: 'lsappinfo list\n")
        doc.append('\n')

        application_list = data_dict["running_applications"]["data"]

        # Generate data table
        with doc.create(LongTable("| p{0.8\linewidth} | p{0.1\linewidth} |", row_height=1.5)) as data_table:
            headers = ["File Path", "Codesign"]
            data_table.add_hline()
            data_table.add_row(headers, mapper=bold)
            data_table.add_hline()
            data_table.end_table_header()
            data_table.add_hline()
            data_table.add_row((MultiColumn(len(headers), align='r',
                                            data=italic('Continued on Next Page')),))
            data_table.end_table_footer()
            data_table.add_hline()
            data_table.add_row((MultiColumn(len(headers), align='r',
                                            data=''),))
            data_table.end_table_last_footer()

            unsigned_apps = []

            for application in application_list:

                verification = application['codesign']['verification']
                if 'valid on disk' in verification[0]:
                    signature = 'Signed'
                    data_table.add_row([application['name'], signature])
                else:
                    signature = 'Unsigned'
                    data_table.add_row([bold(application['name']), bold(signature)])
                    unsigned_apps.append(application)
                data_table.add_hline()

        doc.append(NewPage())
        for application in unsigned_apps:
            with doc.create(Subsubsection(f'UNSIGNED: {application["name"]}')):

                # Small hack to create a new line after subsection
                doc.append(HorizontalSpace('1mm'))
                doc.append('\n')

                doc.append(bold('Application details: \n'))
                doc.append(NewLine())

                first_line = True
                for line in application['details']:
                    line.strip()
                    if not first_line:
                        doc.append(HorizontalSpace('6mm'))
                    first_line = False
                    doc.append(line)
                    doc.append(NewLine())
                doc.append(NewLine())
                doc.append(bold('MD5: '))
                doc.append(application['metadata']['md5'])
                doc.append(NewLine())
                doc.append(bold('SHA1: '))
                doc.append(application['metadata']['sha1'])
                doc.append(NewLine())
                doc.append(bold('SHA256: '))
                doc.append(application['metadata']['sha256'])
                doc.append(NewLine())
                doc.append(NewLine())















