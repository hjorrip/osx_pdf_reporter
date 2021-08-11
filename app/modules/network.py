import json
from pylatex import *
from pylatex.utils import *
from modules.helpers import append_plist_to_doc, split_long_lines


def network(doc: Document, data_location: str, args):

    doc.append(NewPage())

    with open(f'{data_location}/network/network.json') as json_file:
        data_dict = json.load(json_file)

    with doc.create(Section('Network')):
        doc.append("Collection of network data that may reveal important information. No conclusion can be "
                   "automatically drawn from this information, so it is up to the analyst to find anomalies "
                   "in these datasets.")
        ifconfig_subsection(doc, data_dict)
        arp_table_subsection(doc, data_dict)
        open_ports_and_connection_subsection(doc, data_dict)
        files_with_open_network_connection_subsection(doc, data_dict)
        auto_proxy_settings_subsection(doc, data_dict)


def auto_proxy_settings_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Auto Proxy Settings')):
        doc.append("Spyware like OnionSpy has been seen to configure these settings to redirect user traffic to a server of the attacker's choosing. Bash command: 'scutil --proxy'\n")
        doc.append('\n')

        doc.append(bold('Configuration:\n'))
        doc.append(NewLine())

        # TODO: At this location.
        for line in data_dict["auto_proxy_settings"]["data"][1]['lines']:

            white_space_counter = 0
            for idx in range(len(line)):
                if line[idx] == ' ':
                    white_space_counter = white_space_counter + 1
                else:
                    break

            doc.append(HorizontalSpace('{}mm'.format(white_space_counter * 2)))
            doc.append(verbatim(line))
            doc.append("\n")


def files_with_open_network_connection_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Files with open network connection')):
        files_with_open_network_connection_data = data_dict["files_with_open_network_connection"]["data"]

        program_dict = {}

        for entry in files_with_open_network_connection_data:
            if entry['PROGRAM'] not in program_dict.keys():
                program_dict[entry['PROGRAM']] = []
                program_dict[entry['PROGRAM']].append(entry)
            else:
                program_dict[entry['PROGRAM']].append(entry)

        filtered_dict = {}
        for k,v in program_dict.items():
            pid_dict = {}
            for line in v:
                if line['PROCESS']['PID'] not in pid_dict:
                    pid_dict[line['PROCESS']['PID']] = []
                    pid_dict[line['PROCESS']['PID']].append(line)
                else:
                    pid_dict[line['PROCESS']['PID']].append(line)
            filtered_dict[k] = pid_dict


        sorted_keys = sorted(filtered_dict.keys(), key=lambda x: x.lower())


        # Dictionary containing list of executables, and if they are signed or not
        signed_dict = {}

        unsigned_filenames = []


        for file in files_with_open_network_connection_data:
            verification = file['PROCESS']['codesign']['verification']
            if 'valid on disk' in verification[0]:
                signature = 'Signed'
            else:
                signature = 'Unsigned'
                unsigned_filenames.append(file['PROGRAM'])

            signed_dict[file['PROCESS']['exe']] = signature

        # create a list of sorted signed_dict.keys() - So I can present the table in a sorted order
        sorted_signatures = sorted(signed_dict.keys(), key=lambda x:x.lower())

        # Display a table which shows all the executables, and their signature status
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

            for exe_path in sorted_signatures:
                exe_path_split = split_long_lines(exe_path, '/', 80)

                if 'Unsigned' in signed_dict[exe_path]:
                    data_table.add_row([bold(exe_path_split), bold(signed_dict[exe_path])])
                else:
                    data_table.add_row([exe_path_split, signed_dict[exe_path]])
                data_table.add_hline()


        # Loop through unsigned filenames, but get only unique entries
        for program_name in list(dict.fromkeys(unsigned_filenames)):

            for key,pid_group in filtered_dict[program_name].items():
                with doc.create(Subsubsection('UNSIGNED: ' + program_name)):

                    path = filtered_dict[program_name][key][0]['PROCESS']['CMD']
                    # Small hack to create a new line after subsection
                    doc.append(HorizontalSpace('1mm'))
                    doc.append('\n')

                    doc.append(HorizontalSpace('5mm'))
                    doc.append(bold('Process Information:'))
                    # Generate data table
                    with doc.create(LongTabu("l|X[l]",  row_height=1.5)) as data_table:
                        headers = ["Key", "Value"]
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

                        data_table.add_row(["User", filtered_dict[program_name][key][0]['USER']])
                        data_table.add_row(["PID", key])
                        data_table.add_row(['CMD', path])
                        data_table.add_row(['MD5', filtered_dict[program_name][key][0]['PROCESS']['metadata']['md5']])
                        data_table.add_row(['SHA1', filtered_dict[program_name][key][0]['PROCESS']['metadata']['sha1']])
                        data_table.add_row(['SHA256', filtered_dict[program_name][key][0]['PROCESS']['metadata']['sha256']])


                    doc.append(bold('Open Connections:'))

                    with doc.create(LongTabu("l|l|X[l]",  row_height=1.5)) as data_table:
                        headers = ["Type", "PROTOCOL", "Name"]
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

                        for line in filtered_dict[program_name][key]:
                            data_table.add_row([line['TYPE'], line['PROTOCOL'], line['CONNECTION']])




def ifconfig_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Ifconfig')):

        ifconfig_data = data_dict["ifconfig"]["data"]

        # Generate data table
        with doc.create(LongTable("l|l", row_height=1.5)) as data_table:
            headers = ["Interface", "Details"]
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

            for entry in ifconfig_data:

                showInterface = True
                interface = next(iter(entry))

                for line in entry[interface]:
                    if showInterface:
                        data_table.add_row([interface, line])
                        showInterface = False
                    else:
                        data_table.add_row(["", line])

                data_table.add_hline()




def arp_table_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Arp table')):

        arp_table_data = data_dict["arp"]["data"]

        # Generate data table
        with doc.create(LongTable("l", row_height=1.5)) as data_table:
            headers = ["arp table"]
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

            for arp_table in arp_table_data:

                for line in arp_table[next(iter(arp_table))]:
                    data_table.add_row([line])


def open_ports_and_connection_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Open ports and connections')):
        doc.append("Malware authors interested in backdoors will often try to set up a server on an "
                   "unused port to listen out for connections. A good example of this is the recent "
                   "Zoom vulnerability, which forced the company to push out an emergency patch in an "
                   "attempt to address a zero-day vulnerability for Mac users. Zoom has been running a "
                   "'hidden server on port 19421 that could potentially expose a live webcam feed to an "
                   "attacker and allow remote code execution.\n")
        doc.append('\n')


        open_ports_and_connection_data = data_dict["open_ports_and_connections"]["data"]

        # Generate data table
        with doc.create(LongTable("c|l|l|l", row_height=1.5)) as data_table:
            headers = ["Protocol", "Local Address", "Foreign Address", "State"]
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


            for entry in open_ports_and_connection_data:

                data_table.add_row([entry['Proto'], entry['Local Address'], entry['Foreign Address'], entry['State']])
















