import json
from pylatex import *
from pylatex.utils import *


def user_accounts(doc: Document, datalocation: str):
    '''This is the main function for this module'''

    with open(f'{datalocation}/user_accounts/user_accounts.json') as json_file:
        data_dict = json.load(json_file)

    # New Page for this Chapter
    doc.append(NewPage())


    with doc.create(Section('User Accounts')):
        doc.append('OSX has a few built in defence mechanisms that are turned on or off by default.')

        # Create a Chapter for All User Accounts
        with doc.create(Subsection('All User Accounts')):

            # Count the number of user accounts and system accounts
            all_users_list = data_dict["all_users"]["data"]
            user_accounts_list = []
            system_accounts_list = []
            for account in all_users_list:
                username = account['username']
                if username.startswith("_"):
                    system_accounts_list.append(account)
                else:
                    user_accounts_list.append(account)
            nr_of_user_accounts = len(user_accounts_list)
            nr_of_system_accounts = len(system_accounts_list)


            doc.append(f"Total of accounts ")
            doc.append(bold(f'{nr_of_user_accounts + nr_of_system_accounts} '))
            doc.append('accounts identified on the host machine. Based on naming convention, there are ')
            doc.append(bold(f'{nr_of_user_accounts} '))
            doc.append('user accounts and ')
            doc.append(bold(f'{nr_of_system_accounts} '))
            doc.append('system-accounts (with system-account names starting with an _underscore). However, there is nothing stopping a malicious actor from creating an account that begins with an underscore.')

            with doc.create(Subsubsection('User Accounts')):
                doc.append('List of Active User Accounts found on the host machine: \n')

                # Generate data table
                with doc.create(LongTable("l|c", row_height=1.5)) as data_table:
                    headers = ["User Name", "User ID"]
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
                    for user in user_accounts_list:
                        data_table.add_row(user.values())

            with doc.create(Subsubsection('System Accounts')):
                doc.append('List of System Accounts can be found in user_accounts.json and / or all_users_data.csv.')


        with doc.create(Subsection('Logged In Users')):
            doc.append('The Following table lists logged in an currently active users.')
            doc.append('\n')


            logged_in_users_list = data_dict["logged_in_users"]["data"]

            # Generate data table
            with doc.create(LongTable('l|l|l|l|l|l', row_height=1.5)) as data_table:

                headers = ['USER', 'TTY', 'FROM', 'LOGIN@', 'IDLE', 'WHAT']

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
                for user in logged_in_users_list:
                    data_table.add_row([user['USER'], user['TTY'], user['FROM'], user['LOGIN@'], user['IDLE'], user['WHAT']])


        with doc.create(Subsection('Login Logout Information')):

            login_logout_info = data_dict["login_logout_information"]["data"]

            # Get unique usernames and start / end timestamp for description.
            # Rebuild usernames list of dict from the usernames list to match
            # The required format for generate_pdf_table function.
            usernames = []
            session_start = []
            for entry in login_logout_info:
                usernames.append(entry['user_name'])
                session_start.append(entry['session_start'])
            usernames = set(usernames)

            doc.append(f"The following table shows unique active users logged by the host system from ")
            doc.append(bold(f'{session_start[-1]} '))
            doc.append('to ')
            doc.append(bold(f'{session_start[0]}'))
            doc.append(f". For full list of details, check out user_accounts.json or login_logout_information.data.csv.\n")
            doc.append(NewLine())

            # Generate data table
            with doc.create(LongTable("c", row_height=1.5)) as data_table:
                headers = ["User Name"]
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
                for username in usernames:
                    data_table.add_row([username])





