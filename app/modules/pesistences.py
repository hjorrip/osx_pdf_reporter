import json
from pylatex import *
from pylatex.utils import *
from modules.helpers import append_plist_to_doc, split_long_lines


def persistences(doc: Document, data_location: str, args):

    doc.append(NewPage())

    with open(f'{data_location}/persistences/persistence.json') as json_file:
        data_dict = json.load(json_file)

    with doc.create(Section('Persisences')):
        doc.append("Whether it's a cryptominer looking for low-risk money-making opportunities, "
                   "adware hijacking browser sessions to inject unwanted search results, "
                   "or malware designed to spy on a user, steal data or traverse an enterprise network, "
                   "there's one thing all threats have in common: the need for a persistent presence on the endpoint. "
                   "On Apple's macOS platform, attackers have a number of different ways to persist from one login or "
                   "reboot to another.")

    # Add the LaunchAgents SubSection to the Docuement
    launch_agents_subsection(doc, data_dict, args)
    launch_daemons_subsection(doc, data_dict, args)
    cron_tabs_subsection(doc, data_dict, args)
    kernel_extensions_subsection(doc, data_dict, args)
    login_items_subsection(doc, data_dict, args)
    periodics_subsection(doc, data_dict, args)
    hooks_subsection(doc, data_dict, args)
    at_jobs_subsection(doc, data_dict, args)
    emond_clients_subsection(doc, data_dict, args)
    configuration_profiles_subsection(doc, data_dict, args)

def configuration_profiles_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Configuration Profiles')):
        doc.append("Profiles are intended for organizational use to allow IT admins to manage machines "
                   "for their users, but their potential for misuse has already been spotted by malware authors. "
                   "Configuration profiles can force a user to use certain browser settings, DNS proxy settings, "
                   "VPN settings and more.\n")
        doc.append(NewLine())

        doc.append("Configuration Profiles are NOT on a host system by default. The contents of each  "
                   "profile should be carefully inspected.\n")
        doc.append(NewLine())
        configuration_profiles_data_list = data_dict["configuration_profiles"]["data"]

        doc.append("Number of configuration profiles detected: ")
        # TODO: Add a configuration_profiles to the system and update the report to include more details when detected
        doc.append(bold(str(len(configuration_profiles_data_list))))

def emond_clients_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Emond Clients')):
        doc.append("Sometime around OSX 10.5 Leopard, Apple introduced a logging mechanism called emond. "
                   "It appears it was never fully developed, and development may have been abandoned by "
                   "Apple for other mechanisms, but it remains available even on macOS 10.15 Catalina. "
                   "This little-known service may not be much use to a Mac admin, but to a threat actor "
                   "one very good reason would be to use it as a persistence mechanism that most macOS "
                   "admins probably wouldn't know to look for.\n")
        doc.append(NewLine())

        doc.append("As emond is almost certainly not used in your environment for any legitimate reason, "
                   "anything found in the emondClient directory should be treated as suspicious.\n")
        doc.append(NewLine())
        emond_clients_data_list = data_dict["emond_clients"]["data"]

        doc.append("Number of emond clients detected: ")
        # TODO: Add a emond client data to the system and update the report to include more details when detected
        doc.append(bold(str(len(emond_clients_data_list))))


def at_jobs_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('At jobs')):
        doc.append("A much less well-known mechanism is at jobs. While these only run once and are not "
                   "enabled by default, they are a sneaky way to run some code on restart. "
                   "The single- use isn't really a problem, since the at job can simply be re-written "
                   "each time the persistence mechanism fires, and these jobs are very unlikely to be "
                   "noticed by most users or indeed many less-experienced admins.\n")
        doc.append(NewLine())

        doc.append("At jobs are not used by the OS by default. All At jobs should be carefully inspected. \n")
        doc.append(NewLine())
        at_jobs_data_list = data_dict["at_jobs"]["data"]

        doc.append("Number of at jobs detected: ")
        # TODO: Add a at job to the system and update the report to include more details on found at jobs
        doc.append(bold(str(len(at_jobs_data_list))))


def hooks_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Hooks')):
        doc.append("LoginHooks and LogoutHooks have been around for years and are rarely used these days, "
                   "but are still a perfectly viable way of running a persistence script on macOS Mojave. "
                   "As the names suggest, these mechanisms run code when the user either logs in or logs out.\n")
        doc.append(NewLine())

        doc.append("Hooks are not used by the OS by default. Any mentions of LoginHook should be carefully inspected. \n")
        doc.append(NewLine())
        hooks_data_list = data_dict["hooks"]["data"]

        doc.append("Number of LoginHooks detected: ")
        # TODO: Add a login hook to the system and update the report to include more details on found loginhooks
        doc.append(bold(str(len(hooks_data_list))))


def periodics_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Periodics')):
        doc.append("Periodics are system scripts that are generally used or maintenance and run on daily, "
                   "weekly and monthly schedule. Unless admins are using their own custom periodic "
                   "scripts, anything showing a different metadata than the core default periodics "
                   "should be treated as suspicious and inspected.\n")
        doc.append(NewLine())

        periodics = data_dict["periodics"]["data"]

        for periodic in periodics:
            interval = next(iter(periodic))
            if interval == "daily":
                list_of_daily_periodics = periodic['daily']
            elif interval == "weekly":
                list_of_weekly_periodics = periodic['weekly']
            elif interval == "monthly":
                list_of_monthly_periodics = periodic['monthly']


        # Generate data table
        with doc.create(LongTable("l|c|c", row_height=1.5)) as data_table:
            headers = ["File Path", "Periodic", "Last Modified"]
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

            # Create a set of last modified values. Set's can only hold unique values, so if in the end
            # It only holds a single value, all of the file shave the same last_modified date.
            last_modified_set = set()

            for periodic in list_of_daily_periodics:
                data_table.add_row([periodic['metadata']['file_path'], "daily", periodic['metadata']['last_modified']])
                last_modified_set.add(periodic['metadata']['last_modified'])
            for periodic in list_of_weekly_periodics:
                data_table.add_row([periodic['metadata']['file_path'], "weekly", periodic['metadata']['last_modified']])
                last_modified_set.add(periodic['metadata']['last_modified'])
            for periodic in list_of_monthly_periodics:
                data_table.add_row([periodic['metadata']['file_path'], "monthly", periodic['metadata']['last_modified']])
                last_modified_set.add(periodic['metadata']['last_modified'])

        doc.append("Datetime consistancy check: ")
        if len(last_modified_set) < 2:
            doc.append(bold("Passed"))
        else:
            doc.append(bold("Failed"))





def login_items_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Login Items')):
        doc.append("Changes made by Apple to Login Items have, resulted in more attractive opportunities "
                   "for malware persistence. Once upon a time, Login Items were easily enumerated through "
                   "the System Preferences utility, but a newer mechanism makes it possible for any installed "
                   "application to launch itself at login time simply by including a Login Item in its own bundle. "
                   "While the intention of this mechanism is for legitimate developers to offer control of "
                   "the login item through the app's user interface, unscrupulous developers of commodity adware "
                   "and PUP software have been abusing this as a persistence trick as it's very difficult for "
                   "users to reliably enumerate which applications actually contain a bundled login item.\n")
        doc.append(NewLine())

        doc.append('The following Login Items were located on the host machine and checked if they carry '
                   'a valid and recognized code signature. Although some legit programs use unsigned Login Items,'
                   'all should be thoroughly checked and validated.')
        doc.append('\n')

        login_items_list = data_dict["login_items"]["data"]

        doc.append(bold(f"There were {len(login_items_list)} Launch Agents found on the host system."))
        doc.append(NewLine())

        unsigned_counter = 0

        # Only generate the table if there is any data to display.
        if login_items_list:
            with doc.create(LongTable("l|c", row_height=1.5)) as data_table:
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

                unsigned_items = []

                for li in login_items_list:

                    verification = li['codesign']['verification']
                    if 'valid on disk' in verification[0]:
                        signature = 'signed'
                        # If verbose version of the report is requested, we add the launchagent to the
                        # Unsigned list, even if it's signed, to generate more details about that specific
                        # LaunchAgent.
                        if args.verbose:
                            unsigned_items.append(li)

                    else:
                        signature = 'unsigned'
                        unsigned_counter = unsigned_counter + 1
                        unsigned_items.append(li)

                    data_table.add_row([li['path'], signature])

            if not unsigned_counter:
                doc.append(bold('No unsigned login items detected.'))

            # The info.plist are quite too large to include in the report.
            else:
                doc.append("Number of unsigned login items detected: ")
                doc.append(bold(str(unsigned_counter)))


def kernel_extensions_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Kernel Extension')):
        doc.append("Kernel extensions are widely used by legitimate software for persistent behavior, "
                   "and we've seen them also used by so-called PUP software like MacKeeper An open-source "
                   "keylogger, logkext, has also been around for some years, but in general kexts are not a "
                   "favoured trick among malware authors as they are comparatively difficult to create, "
                   "lack stealth, and can be easily removed Moreover, with the advent of macOS 10.15 Catalina, "
                   "Apple have formerly deprecated kernel extensions and appear to be moving rapidly to "
                   "phase them out entirely possibly as early as by 10.16 or 10.17\n")
        doc.append(NewLine())

        doc.append('The following Kernal Extensions were located on the host machine and checked if they carry '
                   'a valid and recognized code signature. '
                   'If any unsigned kernel extension are found, they must be carefully inspected.')
        doc.append('\n')

        kex_list = data_dict["kernel_extensions"]["data"]

        # Generate data table
        with doc.create(LongTable("l|c", row_height=1.5)) as data_table:
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

            unsigned_kex = []


            for kex in kex_list:
                kex_details = kex[next(iter(kex))]
                verification = kex_details['codesign']['verification']
                if 'valid on disk' in verification[0]:
                    signature = 'signed'
                else:
                    signature = 'unsigned'

                    unsigned_kex.append(kex)

                data_table.add_row([kex_details['path'], signature])

        if len(unsigned_kex) == 0:
            doc.append(bold('No unsigned kernel extensions detected.'))

        # The info.plist are quite too large to include in the report.
        else:
            doc.append("Number of unsigned kernel extension detected: ")
            doc.append(bold(str(len(unsigned_kex))))


def cron_tabs_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('Cron Tabs')):

        doc.append("Malicious cron tabs (cron jobs) are used by AdLoad and Mughthesec malware, among others, to "
                   "achieve persistence. Although Apple has announced that new cron jobs will require "
                   "user interaction to install in 10.15 Catalina, it's unlikely that this will do much "
                   "to hinder attackers using it as a persistence method. User prompts are not an "
                   "effective security measure when the user has already been tricked into installing "
                   "the malicious software under the guise of something else. \n")
        doc.append(NewLine())

        doc.append("Cron tabs are NOT on used by the host system by default. "
                   "The validity of each cron tab found on the system must be verified.\n")
        doc.append(NewLine())

        # TODO: Add a cron tab to the system and implement reporting for each cron tab found.
        cron_tabs = data_dict["cron_tabs"]["data"]
        no_cron_tabs = len(cron_tabs)
        doc.append('Number Of CronTabs found: ')
        doc.append(bold(str(no_cron_tabs)))




def launch_daemons_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('LaunchDaemons')):
        doc.append("LaunchDaemons only exist at the computer and system level, and "
                   "technically are reserved for persistent code that does not interact with the user - "
                   "perfect for malware. The bar is raised for attackers as writing a daemon "
                   "to /Library/LaunchDaemons requires administrator level privileges. "
                   "However, since most Mac users are also admin users and habitually provide authorisation "
                   "for software to install components whenever asked, the bar is not all that high and is "
                   "regularly cleared by infections we see in the wild.\n")
        doc.append('\n')

        doc.append('The following LaunchDaemons were located on the host machine and checked if they carry '
                   'a valid and recognized code signature. Although some legit programs use unsigned LaunchDaemons,'
                   'all should be thoroughly checked and validated.')
        doc.append('\n')


        launch_daemons = data_dict["launch_daemons"]["data"]

        doc.append(bold(f"There were {len(launch_daemons)} Launch Daemons found on the host system."))
        doc.append(NewLine())
        # Only generate the table if there is any data to display.
        if launch_daemons:
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

                unsigned_agents = []

                for la in launch_daemons:

                    verification = la['plist_executable']['codesign']['verification']
                    if 'valid on disk' in verification[0]:
                        signature = 'Signed'
                        if args.verbose:
                            # If verbose version of the report is requested, we add the launchagent to the
                            # Unsigned list, even if it's signed, to generate more details about that specific
                            # LaunchAgent.
                            unsigned_agents.append(la)
                    else:
                        signature = 'Unsigned'

                        unsigned_agents.append(la)

                    data_table.add_row([la['filepath'], ""])

                    plist_exe_path = split_long_lines(la['plist_executable']['metadata']['file_path'], '/', 80)

                    data_table.add_row([plist_exe_path, signature])
                    data_table.add_hline()

            if len(unsigned_agents) > 0:

                for plist in unsigned_agents:
                    for key, value in plist.items():
                        if '.plist' in key:
                            plist_name = key
                            with doc.create(Subsubsection(f'{plist_name}')):
                                with doc.create(MiniPage(width=r"0.5\textwidth")):
                                    append_plist_to_doc(doc, plist[plist_name])

                                doc.append(NewLine())

                                doc.append(bold('File Type: '))
                                # The filetype node contains the full path of the file - we dont need to print that
                                # so we find the first semidot and only print the information found after that.
                                file_type = str(plist['plist_executable']['metadata']['filetype']).rstrip()
                                split_index = file_type.find(':') + 1
                                doc.append(file_type[split_index:])

                                doc.append(NewLine())

                                doc.append(bold('MD5: '))
                                doc.append(plist['plist_executable']['metadata']['md5'])

                                doc.append(NewLine())

                                doc.append(bold('SHA1: '))
                                doc.append(plist['plist_executable']['metadata']['sha1'])

                                doc.append(NewLine())

                                doc.append(bold('SHA256: '))
                                doc.append(plist['plist_executable']['metadata']['sha256'])

                                doc.append(NewLine())
                                doc.append(NewLine())




def launch_agents_subsection(doc: Document, data_dict: dict, args):
    with doc.create(Subsection('LaunchAgents')):
        doc.append("By far the most common way malware persists on macOS is via a LaunchAgent. "
                   "Each user on a Mac can have a LaunchAgents folder in their own Library folder "
                   "to specify code that should be run every time that user logs in. "
                   "In addition, a LaunchAgents folder exists at the computer level which can run "
                   "code for all users that login. There is also a LaunchAgents folder reserved "
                   "for the System's own use. However, since this folder is now managed by macOS "
                   "itself (since 10.11), malware is locked out of this location by default so long as "
                   "System Integrity Protection has not been disabled or bypassed. \n")
        doc.append('\n')

        doc.append('The following LaunchAgents were located on the host machine and checked if they carry '
                   'a valid and recognized code signature. Although some legit programs use unsigned LaunchAgents,'
                   'all should be thoroughly checked and validated.')
        doc.append('\n')

        launch_agents = data_dict["launch_agents"]["data"]

        doc.append(bold(f"There were {len(launch_agents)} Launch Agents found on the host system."))
        doc.append(NewLine())
        # Only generate the table if there is any data to display.
        if launch_agents:
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

                unsigned_agents = []
                

                for la in launch_agents:

                    verification = la['plist_executable']['codesign']['verification']
                    if 'valid on disk' in verification[0]:
                        signature = 'Signed'
                        # If verbose version of the report is requested, we add the launchagent to the
                        # Unsigned list, even if it's signed, to generate more details about that specific
                        # LaunchAgent.
                        if args.verbose:
                            unsigned_agents.append(la)
                    else:
                        signature = 'Unsigned'

                        unsigned_agents.append(la)

                    data_table.add_row([la['filepath'], ""])

                    plist_exe_path = split_long_lines(la['plist_executable']['metadata']['file_path'], '/', 90)

                    data_table.add_row([plist_exe_path, signature])
                    data_table.add_hline()


            if len(unsigned_agents) > 0:

                for plist in unsigned_agents:
                    for key, value in plist.items():
                        if '.plist' in key:
                            plist_name = key
                            with doc.create(Subsubsection(f'{plist_name}')):
                                with doc.create(MiniPage(width=r"0.5\textwidth")):
                                    append_plist_to_doc(doc, plist[plist_name])

                                doc.append(NewLine())
                                doc.append(bold('File Type: '))

                                # The filetype node contains the full path of the file - we dont need to print that
                                # so we find the first semidot and only print the information found after that.
                                file_type = str(plist['plist_executable']['metadata']['filetype'])
                                split_index = file_type.find(':') + 1

                                doc.append(file_type[split_index:])
                                doc.append(bold('MD5: '))
                                doc.append(plist['plist_executable']['metadata']['md5'])
                                doc.append(NewLine())
                                doc.append(bold('SHA1: '))
                                doc.append(plist['plist_executable']['metadata']['sha1'])
                                doc.append(NewLine())
                                doc.append(bold('SHA256: '))
                                doc.append(plist['plist_executable']['metadata']['sha256'])
                                doc.append(NewLine())
                                doc.append(NewLine())











