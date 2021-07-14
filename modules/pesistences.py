import json
from pylatex import *
from pylatex.utils import *

from modules.helpers import append_plist_to_doc



def persistences(doc: Document, data_location: str):

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
    launch_agents_subsection(doc, data_dict)
    launch_daemons_subsection(doc, data_dict)
    cron_tabs_subsection(doc, data_dict)


def cron_tabs_subsection(doc: Document, data_dict: dict):
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


def launch_daemons_subsection(doc: Document, data_dict: dict):
    with doc.create(Subsection('LaunchDaemons')):
        doc.append("LaunchDaemons only exist at the computer and system level, and "
                   "technically are reserved for persistent code that does not interact with the user - "
                   "perfect for malware. The bar is raised for attackers as writing a daemon "
                   "to /Library/LaunchDaemons requires administrator level privileges. "
                   "However, since most Mac users are also admin users and habitually provide authorisation "
                   "for software to install components whenever asked, the bar is not all that high and is "
                   "regularly cleared by infections we see in the wild.\n")
        doc.append('\n')
        
        launch_daemons = data_dict["launch_daemons"]["data"]

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

            unsigned_daemons = []

            for la in launch_daemons:

                verification = la['codesign']['verification']
                if 'valid on disk' in verification[0]:
                    signature = 'signed'
                else:
                    signature = 'unsigned'

                    unsigned_daemons.append(la)

                data_table.add_row([la['filepath'], signature])


            for agent in unsigned_daemons:
                del agent['codesign']
                del agent['filepath']



        if len(unsigned_daemons) > 0:

            for plist in unsigned_daemons:
                plist_name = next(iter(plist))
                with doc.create(Subsubsection(f'UNSIGNED: {plist_name}')):
                    with doc.create(MiniPage(width=r"0.5\textwidth")):
                        append_plist_to_doc(doc, plist)
                    doc.append(NewLine())


def launch_agents_subsection(doc: Document, data_dict: dict):
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

            unsigned_agents = []

            for la in launch_agents:

                verification = la['codesign']['verification']
                if 'valid on disk' in verification[0]:
                    signature = 'signed'
                else:
                    signature = 'unsigned'

                    unsigned_agents.append(la)

                data_table.add_row([la['filepath'], signature])


            for agent in unsigned_agents:
                del agent['codesign']
                del agent['filepath']



        if len(unsigned_agents) > 0:

            for plist in unsigned_agents:
                plist_name = next(iter(plist))
                with doc.create(Subsubsection(f'UNSIGNED: {plist_name}')):
                    with doc.create(MiniPage(width=r"0.5\textwidth")):
                        append_plist_to_doc(doc, plist)
                    doc.append(NewLine())
