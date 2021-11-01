import getpass
import requests
import urllib3
import yaml
from invoke import UnexpectedExit
from requests.auth import HTTPBasicAuth
from yaml.loader import SafeLoader
from time import sleep
from fabric import Connection, Config
from paramiko.ssh_exception import NoValidConnectionsError, AuthenticationException

# Read inventory and config data from file
inv_file_path = 'inventory.yml'
with open(inv_file_path) as inv_file:
    inv_data = yaml.load(inv_file, Loader=SafeLoader)

roles = inv_data['service']['splunk']['roles']
config = inv_data['service']['splunk']['config']

# Disable bad cert warnings when config['verify_tls'] is false
verify_tls = config['verify_tls']
if not verify_tls:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def init_obj(obj_name):
    """
    Simple object creation to allow setting attributes on an empty object

    :param obj_name: Name for obj
    :return: Object that can have attributes set
    """
    ret = type(obj_name, (object,), {})
    return ret


def set_pass(passwd, msg=''):
    """
    Check if passwd is set via config or prompts the user if no value set

    :param passwd: Value of password
    :param msg: Message for password prompt
    :return: String for password
    """
    if passwd:
        ret = passwd
    else:
        ret = getpass.getpass(msg)

    return ret


def connect(host, user, passwd=''):
    """
    Setup SSH connection to a host

    :param host: Hostname of an instance to connect to
    :param user: Username to use when connecting
    :param passwd: Password to use for username
    :return: A connection object
    """
    override = Config(overrides={'sudo': {'password': passwd}})
    ret = Connection(host=host, user=user, config=override, connect_kwargs={"password": passwd})
    return ret


def join_api_url(api_base_url, api_path):
    """
    Simple join of a base url and an api path

    :param api_base_url: String representing the base url to use when connecting
    :param api_path: String representing the api path
    :return: A joined url with path
    """
    if api_base_url.endswith('/'):
        api_base_url = api_base_url[:-1]
    if api_path.startswith('/'):
        api_path = api_path[1:]

    return api_base_url + '/' + api_path


def check_status(con):
    """
    Check status by verifying Splunkd is running using sudo

    :param con: Connection obj
    :return: True if is running else false
    """
    try:
        status = con.sudo('su - splunk -c "/opt/splunk/bin/splunk status"', hide=True)
        if 'is running' in status.stdout:
            return True
        else:
            return False
    except (ConnectionError, AuthenticationException, NoValidConnectionsError, UnexpectedExit):
        return False


def patch_os(con, os_family='RHEL'):
    """
    Run the command to patch the OS using sudo.

    :param con: Connection obj
    :param os_family: Set the value for os family i.e. RHEL, Debian, etc
    :return: Result from command
    """
    try:
        result = init_obj('result')
        result.stdout = ''

        # Check OS family and run the appropriate update commands
        if os_family.upper() == 'RHEL':
            result = con.sudo('yum update -y', hide=True)
        elif os_family.upper() == 'DEBIAN':
            # TODO: This needs more work
            con.sudo('apt-get update -y', hide=True)
            result = con.sudo('apt-get dist-upgrade -y', hide=True)

        # Get results and set the proper return value
        ret = 'OS Type not supported'
        if 'Complete!' in result.stdout and 'Nothing to do' not in result.stdout:
            ret = 'Updates complete'
        elif 'Complete!' in result.stdout and 'Nothing to do' in result.stdout:
            ret = 'No Updates'

    except (ConnectionError, NoValidConnectionsError):
        ret = 'Connection error'

    return ret


def cmd_wait(con, run_cmd):
    """
    Command will be retried until success unless range value is reached

    :param con: Connection obj
    :param run_cmd: Command to run
    :return: Result from command
    """
    # May take up to 5 minutes
    sleep(5)
    ret = False
    for _ in range(25):
        try:
            result = con.run(run_cmd, hide=True)
            if result.return_code == 0:
                ret = True
            break
        except (ConnectionError, NoValidConnectionsError):
            sleep(10)

    return ret


def check_maintenance_mode(api_url, user, user_pass, verify=False):
    """
    Check if maintenance mode is enabled, or disabled based on the value set for maintenance_mode

    :param api_url: String representing the base url to use when connecting
    :param user: Rest User to use when connecting
    :param user_pass: Password to use for Rest User
    :param verify: Verify TLS
    :return: Enabled, disabled, or unknown depending on requests value
    """
    try:
        ret = requests.get(api_url, auth=HTTPBasicAuth(user, user_pass), verify=verify)
        if ret.json()['entry'][0]['content']['maintenance_mode']:
            return 'enabled'
        else:
            return 'disabled'
    except (ConnectionError, NoValidConnectionsError):
        return 'unknown'


def set_maintenance_mode(api_set_mm, user, user_pass, data, verify=False):
    """
    Set maintenance mode status based on mode passed in as data

    :param api_set_mm: String representing the base url to use when connecting
    :param user: Rest User to use when connecting
    :param user_pass: Password to use for Rest User
    :param data: Mode value is True or False
    :param verify: Verify TLS
    :return: Result from API
    """
    try:
        ret = requests.post(api_set_mm, auth=HTTPBasicAuth(user, user_pass), data=data, verify=verify)
    except (ConnectionError, NoValidConnectionsError):
        ret = 'Connection error'

    return ret


# Set up account credentials
username = config['system_user']
password = None
if 'system_user_pass' in config:
    password = set_pass(config['system_user_pass'], "Enter user password: ")

splunk_user = config['splunk_user']
splunk_user_pass = None
if 'splunk_user_pass' in config:
    splunk_user_pass = set_pass(config['splunk_user_pass'], "Enter Splunk user password: ")

# Join API url and path for maintenance mode status check
check_status_url = join_api_url(config['splunk_cm_api_url'], config['splunk_status_check_path'])

# False is the expected value but we return disabled.
if check_maintenance_mode(check_status_url, splunk_user, splunk_user_pass, verify_tls) == 'disabled':
    # Perform checks to verify ready to start
    for role in roles.keys():
        for hostname in roles[role]:
            # Create a new session and check Splunkd status
            session = connect(hostname, username, password)
            if check_status(session):
                print('[OK] Splunkd is running: ' + hostname)
            else:
                print('[FAIL] Status Check: ' + hostname)
                # Close session and exit
                session.close()
                exit(1)

            # Close session and continue
            session.close()
else:
    # Maintenance mode is already enabled.
    # We should find out why and try again
    print('[FAIL] Maintenance mode already enabled')
    exit(1)

print('[OK] All status checks passed... Proceeding')

# Join API url and path for setting maintenance mode value
splunk_api_set_mm = join_api_url(config['splunk_cm_api_url'], config['splunk_set_mm_path'])

# Status checks have passed, do the updates
for role in roles.keys():
    # Set maintenance mode status to true
    # Only needs to be done for the indexers
    if role == 'idx':
        rest_data = {'mode': 'true'}
        res = set_maintenance_mode(splunk_api_set_mm, splunk_user, splunk_user_pass, rest_data, verify_tls)
        if check_maintenance_mode(check_status_url, splunk_user, splunk_user_pass, verify_tls) != 'enabled':
            print('[FAIL] Maintenance mode not enabled:')
            exit(1)

    # Iterate through list of hosts assigned to this role
    for hostname in roles[role]:
        # Create session
        session = connect(hostname, username, password)

        # Update host if patches available
        is_updated = patch_os(session)
        if is_updated == 'Updates complete':
            print('[OK] OS Updates complete: ' + hostname)
            if role == 'idx':
                # Take splunk indexer offline
                offline_cmd = 'su - splunk -c "/opt/splunk/bin/splunk offline -auth {}:{}"'.format(splunk_user, splunk_user_pass)
                idx_offline = session.sudo(offline_cmd, hide=True)
                if idx_offline.return_code == 0:
                    print('[OK] Splunkd is offline: ' + hostname)

            # Reboot host if patches applied
            is_rebooted = session.sudo('nohup sudo -b bash -c "sleep 5 && reboot"', hide=True)
            if is_rebooted.return_code == 0:
                is_running = cmd_wait(session, 'systemctl status Splunkd.service')
                if is_running:
                    print('[OK] Splunkd is running: ' + hostname)
                    print('[OK] Reboot successful: ' + hostname)
                else:
                    print('[FAIL] Status Check: ' + hostname)
                    session.close()
                    exit(1)
            else:
                print('[FAIL] Something went wrong - Aborting: ' + hostname)
                session.close()
                exit(1)
        elif is_updated == 'Connection error':
            print('[FAIL] Connection error - Aborting: ' + hostname)
            session.close()
            exit(1)
        elif is_updated == 'OS Type not supported':
            print('[WARN] OS Type not supported - No Updates: ' + hostname)
        else:
            print('[OK] No updates: ' + hostname)

        # Close session
        session.close()

    # Set maintenance mode status to false
    # Only needs to be done for the indexers
    if role == 'idx':
        rest_data = {'mode': 'false'}
        res = set_maintenance_mode(splunk_api_set_mm, splunk_user, splunk_user_pass, rest_data, verify_tls)
        if check_maintenance_mode(check_status_url, splunk_user, splunk_user_pass, verify_tls) != 'disabled':
            print('[FAIL] Maintenance mode not disabled:')
            exit(1)

print('[OK] All hosts finished. Complete!')
