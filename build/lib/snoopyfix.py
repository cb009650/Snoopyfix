import misconfig , subprocess , shlex , os ,sys,colorama ,shutil
list_of_total_misconfigurations = []



def center_text(text):
    # Get the width of the terminal/console window
    terminal_width, _ = shutil.get_terminal_size()

    # Split the text into lines and get the maximum line length
    lines = text.split('\n')
    max_line_length = max(len(line) for line in lines)

    # Calculate the number of spaces needed to center the text
    spaces_needed = (terminal_width - max_line_length) // 2

    # Center the text by adding the appropriate number of spaces before each line
    centered_text = '\n'.join(' ' * spaces_needed + line for line in lines)

    return centered_text


def Asses_Telnet():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' telnet"
    exec_result = Execute_command(command)
    if (exec_result.stdout.__contains__("telnet\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        misconfiguration = misconfig.Misconfiguration("NETWORK SERVICES",["telnet is installed"])
        list_of_total_misconfigurations.append(misconfiguration)
      
def Asses_LDAP():

    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' slapd"
    exec_result = Execute_command(command)
    print(exec_result)
    if (exec_result.stdout.__contains__("slapd\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        print("ldp client is installed")
        # misconfiguration = misconfig.Misconfiguration("NETWORK SERVICES",["telnet is installed"])
        # list_of_total_misconfigurations.append(misconfiguration)


def Asses_NIS():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis"
    exec_result = Execute_command(command)
    print(exec_result)
    if (exec_result.stdout.__contains__("nis\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        print("nis client is installed")
        # misconfiguration = misconfig.Misconfiguration("NETWORK SERVICES",["telnet is installed"])
        # list_of_total_misconfigurations.append(misconfiguration)
def Asses_RPC():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rpcbind"
    exec_result = Execute_command(command)
    print(exec_result)
    print(exec_result.returncode)
    if (exec_result.stdout.__contains__("rpcbind\tunknown ok not-installed\tnot-installed") or exec_result.stderr):
        print("rpc client is not installed")
        pass
    else :
        print("rpc client is installed")
        # misconfiguration = misconfig.Misconfiguration("NETWORK SERVICES",["telnet is installed"])
        # list_of_total_misconfigurations.append(misconfiguration)
def Asses_talkClient():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' talk"
    exec_result = Execute_command(command)
    print(exec_result)
    if (exec_result.stdout.__contains__("talk\tunknown ok not-installed\tnot-installed") or exec_result.stderr):
        print("talk client is not installed")
        pass
    else :
        print("talk client is installed")
        # misconfiguration = misconfig.Misconfiguration("NETWORK SERVICES",["telnet is installed"])
        # list_of_total_misconfigurations.append(misconfiguration)
      
      
def Asses_auditd ():
    local_misconfigurations = []
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' auditd audispd-plugins"
    exec_result = Execute_command(command)
    if (exec_result.stdout.__contains__("installed")):
       
        auditd_enabled_command= "systemctl is-enabled auditd"
        auditd_active_command = "systemctl is-active auditd"
        auditd_enabled_status = Execute_command(auditd_enabled_command)
        auditd_active_status = Execute_command(auditd_active_command)
        if (auditd_enabled_status.stdout == "enabled" and auditd_active_status.stdout == "active"):
            pass
        else:
            local_misconfigurations.append("auditd is not enabled/active")


    else:
        local_misconfigurations.append("auditd is not installed")
    
    audit_misconfiguration = misconfig.Misconfiguration("AUDITD",local_misconfigurations)
    list_of_total_misconfigurations.append(audit_misconfiguration)




def Execute_command(command):
    exec_result = subprocess.run(shlex.split(command),capture_output=True,text=True)
    return exec_result



# the function returns user level of the user that is been logged in

def Check_for_root_priviledges ():
    user_status = ""
    if (os.geteuid() == 0):
        user_status = "ROOT"
    else:
        user_status = "GENERAL_USER"
    return user_status

# The function check the correct version of Ubuntu is installed (Ubuntu 22.04.2 LTS) and will return true if the condition is satisfied
def Check_for_OS_version():
    command = "grep -i 'pretty_name' /etc/os-release"
    version =  Execute_command(command)
    correct_version =False
    if (version.stdout =='PRETTY_NAME="Ubuntu 22.04.2 LTS"\n'):
        correct_version = True
    else:
        correct_version = False
    return correct_version

# the function returns true if the coorect python version is installed in the system
def Get_python_version ():
    python_version = str(sys.version_info.major) +"."+ str(sys.version_info.minor)
    python_version = float(python_version)
  
    supportability = False
    if (python_version >= 2.4):
        supportability = True
    else:
        supportability = False
    return supportability

def Display_Misconfigurations():
    
    if (len(list_of_total_misconfigurations) != 0 ):
        print(colorama.Fore.RED+"WARNING!!!!".center(45) +colorama.Style.RESET_ALL)
        print("=============================================")
        print("The Following Misconfigurations Were Detected".upper())
        print("=============================================\n")
        for misconfiguration in list_of_total_misconfigurations:
            print(f"{len(misconfiguration.list_of_misconfigurations)} issue/s were found relating to the {misconfiguration.misconfiguration_name.lower()}")
            for individual_misconfiguration in misconfiguration.list_of_misconfigurations:
                print(f"[*] {individual_misconfiguration}")
        
    else:
        print(colorama.Fore.GREEN+"no misconfigurations were found in the system")

def fix_misconfigurations():
    print("fixing mis configurations")
       
def init():
    ROOT_LEVEL = Check_for_root_priviledges()
    CORRECT_PYTHON_VERSION = Get_python_version()
    UBUNTU_VERSION = Check_for_OS_version()
   
    if (ROOT_LEVEL == "GENERAL_USER"):
        print("The above script requires root permission to be executed")
        return
    if (CORRECT_PYTHON_VERSION == False):
        print("The script requires a python version of 3 or above")
        return
    if (UBUNTU_VERSION == False):
        print("The script only works for Ubuntu 22.04.2 LTS version")
        return
    command = "bash firewall.sh"
    result = Execute_command(command)
    ports = [item for item in result.stdout.split("\n") if item not in ['','missing a firewall rule']]
    for port in ports:
        required_port = port.split(" ")
        required_port = required_port[2].strip('"')
        print( type(int(required_port)))

    
    Asses_auditd()
    Asses_Telnet()
    Asses_LDAP()
    Asses_NIS()
    Asses_RPC()
    Asses_talkClient()
    Display_Misconfigurations()
    for symbol in range(0,3):
            print("\n")
    user_choice = input(colorama.Fore.YELLOW+"Do you want to fix the found misconfigurations(Y/N)?"+colorama.Fore.RESET)
    if (user_choice.lower() == "y" or user_choice.lower() == "yes"):
        fix_misconfigurations()
    else:
        pass



def main_introduction():
    banner = colorama.Fore.GREEN+"""\
       ,-~~-.___.               __  __      _   _  _
      / |  x     \             █▀ █▄░█ █▀█ █▀█ █▀█ █▄█   █▀▀ █ ▀▄▀
     (  )        0             ▄█ █░▀█ █▄█ █▄█ █▀▀ ░█░   █▀░ █ █░█(Ubuntu 22.04.2 LTS version)
      \_/-, ,----'  ____        
         ====      ||   \_ 
        /  \-'~;   ||     |                v.1.0.0
       /  __/~| ...||__/|-"   Your one and only OS hardening automated tool for your operating system
     =(  _____||________|                  -- A project by APIIT SOC --
    """

    print(center_text(banner))
    print("===============")
    print("ABOUT US".center(15))
    print("===============\n")
    print("The OSHARDX script was originally developed for the XYZ company to improve the security postures of XYZ's machines which run Ubuntu 22.04.2 LTS edition.")

    print("===============")
    print("USAGE".center(16))
    print("===============\n")
    print('To use the script "sudo python3 oshard.py" or python3 oshard.py with root priviledges\n ')
    print("===============")
    print("TROUBLESHOOTING")
    print("===============\n")
    print("Please make sure the following requirements are satisfied:\n")
    print(colorama.Fore.YELLOW+"[*] A python version of 3.10.6 or above is installed in the system to avoid any compatability issues")
    print("[*] A Ubuntu 22.04.2 LTS version Operating System")
    print("[*] The script is executed with Root Priviledges\n"+colorama.Fore.RESET)
    print("Once the script has been executed if any service needs to be re-installed for any additional use please install them separately.\n")
    for symbol in range(0,3):
                print("\n")
    user_input = input("I have read the terms of conditions of OSHARD and understand the effects of executing the script[yes/no]:")
    if (user_input.lower() == "yes" or user_input.lower() =="y"):
        for symbol in range(0,3):
                print("\n")
        init()
    else:
        pass



def main():
    main_introduction()

if __name__ == "__main__":
    main()


