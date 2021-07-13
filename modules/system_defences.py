import json
from pylatex import *
from pylatex.utils import *


def system_defences(doc: Document, data_location: str):

    with open(f'{data_location}/defences/defences.json') as json_file:
        data_dict = json.load(json_file)


    doc.append(NewPage())

    with doc.create(Section('System Defences')):
        doc.append('OSX has a few built in defence mechanisms that are turned on or off by default.')


        with doc.create(Subsection('System Integrity Protection')):
            doc.append('System Integrity Protection restricts the root user account and limits the action that the root user can perform on proteted parts of the mac operating system. SIP should be turned on and is enabled by default')
            doc.append('\n')
            doc.append('\n')


            sip_status = data_dict["system_integrity_protection"]["data"][0]["System Integrity Protection status"]
            doc.append('System Integrity Protection status: ')
            doc.append(bold(sip_status.capitalize()))

        with doc.create(Subsection('OSX Firewall')):
            doc.append('The build-in OSX Firewall is disabled by default.')
            doc.append('\n')
            doc.append('\n')

            osx_firewall_status = data_dict["osx_firewall"]["data"][0]["OSX Firewall Status"]
            doc.append(f'System Integrity Protection status: ')
            doc.append(bold(osx_firewall_status))

        with doc.create(Subsection('SecAssessment System Policy Security')):
            doc.append('This subsystem maintains and evaluates rules that determine whether the system allows the installation, executin, and other operations on files on the system. SecAssessment System Policy Security is enabled by default.')
            doc.append('\n')
            doc.append('\n')

            assessments = data_dict["secassessment_system_policy_security"]["data"][0]["assessments"]
            doc.append(f'System Integrity Protection status: ')
            doc.append(bold(assessments.capitalize()))


    