import json
import re

from pylatex import *
from pylatex.utils import *
from modules.helpers import append_plist_to_doc, split_long_lines, line_wrapper


def processes(doc: Document, data_location: str):

    doc.append(NewPage())

    with open(f'{data_location}/processes/processes.json') as json_file:
        data_dict = json.load(json_file)

    #TODO: DElete / move
    #with open(f'{data_location}/files/files.json') as json_file:
    #    files_dict = json.load(json_file)

    with doc.create(Section('Processes')):
        doc.append("Collection of process data that may reveal important information. No conclusion can be "
                   "automatically drawn from this information, so it is up to the analyst to find anomalies "
                   "in these datasets.")

        running_applications_subsection(doc, data_dict)
        launchctl_list_subsection(doc, data_dict)
        running_processes_subsection(doc, data_dict)

        #TODO: Delete/move
        #open_files(doc, files_dict)




# TODO: Delete / move
def open_files(doc:Document, data_dict: dict):

    open_files_data = data_dict["list_of_open_files"]["data"]

    system_files = []
    other_files = []
    other_regular_files = []

    for file in open_files_data:

        file_path = file['NAME']

        if str(file_path).startswith('/System'):
            system_files.append(file)
        else:

            if file['TYPE'] == 'REG':
                other_regular_files.append(file)
            else:
                other_files.append(file)

    print(f'System Files: {len(system_files)}')
    print(f'Other Files: {len(other_files)}')
    print(f'Other Regular Files: {len(other_regular_files)}')



def running_processes_subsection(doc: Document, data_dict: dict):

    # TODO: Implement flags to flip this bit when requested
    verbose = False


    running_processes_data = data_dict["running_processes"]["data"]

    # ******************************* Data sorting *******************************
    # We want to get a list of processes that do not carry the PPID 0 or 1,
    # Meaning a list of processes that WERE NOT spawned by the system, but rather
    # indicating a user spawning a child process

    user_spawned_processes = []
    # Dictionary that pairs PID with Command
    process_dict = {}

    # Basic filter, grab all of the proceses that do not carry PPID 0 or 1
    for process in running_processes_data:

        process_info = {}

        program_path = process['PROGRAM']
        process_info['PROGRAM'] = program_path

        command = process['COMMAND']
        arguments = str(command).replace(program_path, '')

        process_info['ARG'] = arguments

        process_dict[process['PID']] = process_info

        ppid = int(process['PPID'])
        if ppid > 1:
            user_spawned_processes.append(process)

    unsigned_processes = []

    # ********* VERBOSE Reporting # *********

    with doc.create(Subsection('Running Processes')):
        doc.append("There were total ")
        doc.append(bold(f'{len(running_processes_data)} '))
        doc.append("processes running on the host system during the data collection.")
        doc.append(NewLine())
        doc.append("Out of those ")
        doc.append(bold(f'{len(running_processes_data)}'))
        doc.append(", ")
        doc.append(bold(f'{len(user_spawned_processes)} '))
        doc.append('were user spawned processes, that is, did not have PPID 0 or 1')
        doc.append(NewLine())
        doc.append(NewLine())

        if verbose:

            for entry in user_spawned_processes:

                path = str(entry['PROGRAM']).split("/")
                program_name = path[-1]

                with doc.create(Subsubsection(program_name)):

                    # TODO Working on table formatting - sometimes the letters go off page
                    # Generate data table
                    with doc.create(LongTable("| p{0.1\linewidth} | p{0.8\linewidth} |", row_height=1.5)) as data_table:
                        nr_of_columns = 2

                        data_table.add_hline()
                        data_table.add_row((MultiColumn(nr_of_columns, align='r',
                                                        data=italic('Continued on Next Page')),))
                        data_table.end_table_footer()
                        data_table.add_hline()
                        data_table.add_row((MultiColumn(nr_of_columns, align='r',
                                                        data=''),))
                        data_table.end_table_last_footer()

                        data_table.add_hline()
                        data_table.add_row(["Spawned by", entry['USER']])
                        data_table.add_hline()

                        data_table.add_row(["PID", entry['PID']])
                        data_table.add_hline()


                        program_path = entry['PROGRAM']

                        data_table.add_row(["Program", line_wrapper(program_path)])
                        data_table.add_hline()



                        command = entry['COMMAND']

                        arguments = command.replace(program_path, '')

                        data_table.add_row(["Arguments", line_wrapper(arguments)])

                        data_table.add_hline()

                        data_table.add_hline()


                        data_table.add_row(["PPID", entry['PPID']])
                        data_table.add_hline()
                        data_table.add_row(["Program", line_wrapper(process_dict[entry['PPID']]['PROGRAM'])])
                        data_table.add_hline()
                        data_table.add_row(["Arguments", line_wrapper(process_dict[entry['PPID']]['ARG'])])
        else:
            # Generate data table
            with doc.create(LongTable("| p{0.05\linewidth}| p{0.05\linewidth} | p{0.7\linewidth} | p{0.1\linewidth} | ",
                                      row_height=1.5)) as data_table:
                headers = ["PPID", "PID", "Program", "Codesign"]
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


                for process in user_spawned_processes:

                    pid = process['PID']
                    ppid = process['PPID']
                    program = process['PROGRAM']

                    verification = process['codesign']['verification']
                    if 'valid on disk' in verification[0]:
                        signature = 'Signed'

                    else:
                        signature = bold('Unsigned')
                        unsigned_processes.append(process)

                    data_table.add_row([ppid, pid, line_wrapper(program), signature])

                    data_table.add_hline()



            for process in unsigned_processes:
                path = str(process['PROGRAM']).split("/")
                program_name = path[-1]
                with doc.create(Subsubsection('Unsigned: ' + program_name)):
                    # TODO Working on table formatting - sometimes the letters go off page
                    # Generate data table
                    with doc.create(
                            LongTable("| p{0.1\linewidth} | p{0.8\linewidth} |", row_height=1.5)) as data_table:
                        nr_of_columns = 2

                        data_table.add_hline()
                        data_table.add_row((MultiColumn(nr_of_columns, align='r',
                                                        data=italic('Continued on Next Page')),))
                        data_table.end_table_footer()
                        data_table.add_hline()
                        data_table.add_row((MultiColumn(nr_of_columns, align='r',
                                                        data=''),))
                        data_table.end_table_last_footer()

                        data_table.add_hline()
                        data_table.add_row(["Spawned by", process['USER']])
                        data_table.add_hline()

                        data_table.add_row(["PID", process['PID']])
                        data_table.add_hline()

                        program_path = process['PROGRAM']
                        path_multiline = split_long_lines(program_path, '/', 80)

                        data_table.add_row(["Program", path_multiline])
                        data_table.add_hline()

                        command = process['COMMAND']

                        arguments = command.replace(program_path, '')

                        data_table.add_row(["Arguments", line_wrapper(arguments)])

                        data_table.add_hline()

                        data_table.add_hline()

                        data_table.add_row(["PPID", process['PPID']])
                        data_table.add_hline()
                        data_table.add_row(["Program", line_wrapper(process_dict[process['PPID']]['PROGRAM'])])
                        data_table.add_hline()
                        data_table.add_row(["Arguments", line_wrapper(process_dict[process['PPID']]['ARG'])])




def launchctl_list_subsection(doc: Document, data_dict: dict):

    launchctl_list_data = data_dict["launchctl_list"]["data"]

    # ******************************* Data sorting *******************************
    apple_safe_launchctl = []
    # May be signed, but do not meet the three criterias below.
    apple_flagged_launchctl = []
    other_signed_launchctl = []
    other_unsigned_launchctl = []

    for launchctl in launchctl_list_data:

        if 'com.apple' in launchctl['Label']:

            # These three need to be turned into for us to belive that those files claiming to be com.apple
            # are really from apple. We read each line in the codesign full_verification and update
            # those booleans if they meet the required values.
            authority_software_signing = False
            authority_apple_code_signing = False
            authority_apple_root = False

            for line in launchctl['details']['codesign']['full_signature']:
                if line == "Authority=Software Signing":
                    authority_software_signing = True
                elif line == "Authority=Apple Code Signing Certification Authority":
                    authority_apple_code_signing = True
                elif line == "Authority=Apple Root CA":
                    authority_apple_root = True

            # If the launcctl meet all of those criterias, we put them in the apple_launchctl list,
            # otherwise, we flag it and put it in the 'flagged' list
            if authority_software_signing and authority_apple_code_signing and authority_apple_root:
                apple_safe_launchctl.append(launchctl)
            else:
                apple_flagged_launchctl.append(launchctl)

        else:
            verification = launchctl['details']['codesign']['verification']
            if 'valid on disk' in verification[0]:
                signature = 'Signed'
                other_signed_launchctl.append(launchctl)
            else:
                signature = 'Unsigned'
                other_unsigned_launchctl.append(launchctl)

    with doc.create(Subsection('Launchctl list')):
        doc.append("Shows running daemons, agents, XPC services and other information on what's running in that particular user's domain. Bash command 'launchctl list'\n")

        doc.append("There were total ")
        doc.append(bold(f'{len(launchctl_list_data)} '))
        doc.append("launchctl items registered on the system.")
        doc.append(NewLine())

        with doc.create(Subsubsection(f'Apple services')):

            total_apple_claims = len(apple_safe_launchctl) + len(apple_flagged_launchctl)

            doc.append(f'System processess carry a label starting with "com.apple.", however, some macOS malware does deliberately use the name "apple" in their labels precisely in an attempt to hide in the weeds. \n')
            doc.append(NewLine())
            doc.append(f'There were total of {total_apple_claims} entries found using the system process naming convention \n')
            doc.append(NewLine())
            doc.append(f"Every service that claimes to originate from apple have been passed through three "
                       f"signature checks. Out of the total {total_apple_claims}, there were {len(apple_flagged_launchctl)} "
                       f"launchctl items that were flagged, whom failed the automatic signature checks.")


            for flagged_launchtl in apple_flagged_launchctl:
                with doc.create(Subsubsection(f'Flagged: {flagged_launchtl["Label"]}')):

                    doc.append(bold('Service path: '))
                    doc.append(flagged_launchtl['details']['service_path'])
                    doc.append(NewLine())
                    doc.append(bold('Process ID: '))
                    doc.append(flagged_launchtl['PID'])
                    doc.append(NewLine())
                    doc.append(bold('Status: '))
                    doc.append(flagged_launchtl['Status'])
                    doc.append(NewLine())
                    doc.append(italic('If the number is negative, it represents the negative of the signal which stopped the job. Thus, "-15" would indicate that the job was terminated with SIGTERM'))
                    doc.append(NewLine())
                    doc.append(NewLine())
                    full_signature = flagged_launchtl['details']['codesign']['full_signature']
                    metadata = flagged_launchtl['details']['metadata']
                    doc.append(bold('Full Code Signature:'))
                    doc.append(NewLine())

                    if len(full_signature) > 0:

                        if len(full_signature) > 1:
                            for line in flagged_launchtl['details']['codesign']['full_signature']:
                                # Each line has has a key=value format, so we split those and make the font weight
                                # for the key bold
                                line_arr = str(line).split("=")
                                doc.append(bold(f"{line_arr[0]} : "))
                                doc.append(" ".join(line_arr[1:]))
                                doc.append(NewLine())

                        else:
                            doc.append(full_signature[0])
                            doc.append(NewLine())

                    else:
                        doc.append('No code-signature found.....')
                        doc.append(NewLine())

                    doc.append(NewLine())
                    doc.append(bold('Metadata:'))
                    doc.append(NewLine())
                    if len(metadata) > 0:
                        for k, v in metadata.items():
                            doc.append(bold(f'{k} : '))
                            clean_value = str(v).replace('\n', '')
                            doc.append(clean_value)
                            doc.append(NewLine())


                    else:
                        doc.append('No meta-data found....')
                        doc.append(NewLine())

        with doc.create(Subsubsection(f'Other services')):
            doc.append(f'Out of ')
            doc.append(bold(f' {len(launchctl_list_data)} '))
            doc.append('launchctl items, there were ')
            total_other_services = len(other_signed_launchctl) + len(other_unsigned_launchctl)
            doc.append(bold(f' {total_other_services} '))
            doc.append(' that are not service items according to the OSX naming convention.')
            doc.append(NewLine())
            doc.append(NewLine())
            doc.append('Out of those ')
            doc.append(bold(f'{total_other_services} '))
            doc.append('there were ')
            doc.append(bold(f'{len(other_unsigned_launchctl)} '))
            doc.append('that are unsigned.')

            # Generate data table
            with doc.create(LongTable("| p{0.8\linewidth} | p{0.1\linewidth} |", row_height=1.5)) as data_table:
                headers = ["Launchctl Item and Service Path", "Codesign"]
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

                for launchctl in other_signed_launchctl:

                    data_table.add_row([bold(launchctl['Label']), ""])

                    service_path = split_long_lines(launchctl['details']['service_path'], '/', 90)

                    data_table.add_row([service_path, "Signed"])
                    data_table.add_hline()

                if len(other_unsigned_launchctl) > 0:
                    for launchctl in other_unsigned_launchctl:

                        data_table.add_row([bold(launchctl['Label']), ""])

                        data_table.add_row([launchctl['details']['service_path'], bold("Unsigned")])
                        data_table.add_hline()

            if len(other_unsigned_launchctl) > 0:
                for launchctl in other_unsigned_launchctl:
                    with doc.create(Subsubsection(f'UNSIGNED: {launchctl["Label"]}')):
                        with doc.create(MiniPage(width=r"0.5\textwidth")):

                            plist = launchctl["details"]["plist"]

                            plist_lines = plist.split('\n')

                            for line in plist_lines:
                                line_indented = str(line).replace('\t', '    ')
                                doc.append(verbatim(line_indented))
                                doc.append(NewLine())
                            #append_plist_to_doc(doc, launchctl["details"]["plist"])

                        doc.append(NewLine())


                        doc.append(bold('File Path: '))
                        doc.append(launchctl['details']['metadata']['file_path'])

                        doc.append(NewLine())

                        doc.append(bold('File Type: '))
                        # The filetype node contains the full path of the file - we dont need to print that
                        # so we find the first semidot and only print the information found after that.
                        file_type = str(launchctl['details']['metadata']['filetype']).rstrip()
                        split_index = file_type.find(':') + 1
                        doc.append(file_type[split_index:])
                        doc.append(NewLine())

                        doc.append(bold('MD5: '))
                        doc.append(launchctl['details']['metadata']['md5'])

                        doc.append(NewLine())

                        doc.append(bold('SHA1: '))
                        doc.append(launchctl['details']['metadata']['sha1'])

                        doc.append(NewLine())

                        doc.append(bold('SHA256: '))
                        doc.append(launchctl['details']['metadata']['sha256'])

                        doc.append(NewLine())
                        doc.append(NewLine())







def running_applications_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('Running Applications')):
        doc.append("Shows the application list and information about each running application. Bash command: 'lsappinfo list\n")
        doc.append('\n')

        application_list = data_dict["running_applications"]["data"]

        # Generate data table
        with doc.create(LongTable("| p{0.65\linewidth} | p{0.15\linewidth} | p{0.1\linewidth} |", row_height=1.5)) as data_table:
            headers = ["File Path", "Type", "Codesign"]
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

                exe_path = ""
                type = "N/A"

                for line in application['details']:
                    if 'executable path' in line:
                        exe_path = re.findall('(?<=executable path=").+(?=")', line)[0]
                    elif 'type' in line:
                        type = re.findall(r'(?<=type=").+?(?=")', line)[0]
                        type = bold(type) if 'BackgroundOnly' in type else type

                verification = application['codesign']['verification']

                if 'valid on disk' in verification[0]:
                    signature = 'Signed'

                    app_name = exe_path if not "" else application['name']

                    data_table.add_row([line_wrapper(app_name), type, signature])
                else:
                    signature = 'Unsigned'
                    data_table.add_row([bold(application['name']), type, bold(signature)])
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














