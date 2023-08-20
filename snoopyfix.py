import misconfig , subprocess , shlex , os ,sys,colorama ,shutil , time, pandas , tabulate

list_of_total_misconfigurations = []

YELLOW= colorama.Fore.YELLOW
RED= colorama.Fore.RED
GREEN =  colorama.Fore.GREEN
BLUE= colorama.Fore.BLUE


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


# ============================================================================================================================================================
#                                                                  SPRINT - 01
# ============================================================================================================================================================
# Developed by Eshen Sanjula Warawita
def Asses_NIS():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis"
    exec_result = Execute_command(command)
    # print(exec_result.stdout + exec_result.stderr)
 
    if (exec_result.stdout.__contains__("nis\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        print("nis client is installed")
        misconfiguration = misconfig.Misconfiguration("NIS is installed","NETWORK SERVICES","Can lead to DoS attacks",Delete_NIS)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_NIS ():
    print("run nis")
    command = "apt purge nis"
    result = Execute_command(command)
    if result.returncode != 1:
        print("successfullt uninstalled NIS")


def Asses_rsh_client():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsh-client"
    exec_result = Execute_command(command)
    # print(exec_result.stdout )
   
    if (exec_result.stdout.__contains__("rsh-client\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        print("rsh-client is installed")
        misconfiguration = misconfig.Misconfiguration("rsh-client is installed","NETWORK SERVICES","These legacy clients contain numerous security exposures",Delete_rsh_client)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_rsh_client ():
    command = "apt purge rsh-client"
    result = Execute_command(command,"Y")
    if result.returncode != 1:
        print("successfullt uninstalled rsh-client")



def Asses_talkClient():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' talk"
    exec_result = Execute_command(command)
    # print(exec_result.stdout + exec_result.stderr)

    if (exec_result.stdout.__contains__("talk\tunknown ok not-installed\tnot-installed") or exec_result.stderr):
        
        pass
    else :
        print("talk client is installed")
        misconfiguration = misconfig.Misconfiguration("talk-client is installed","NETWORK SERVICES","Can lead to DoS attacks",Delete_talk_client)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_talk_client ():
    print("run talk")
    command = "apt purge talk"
    result = Execute_command(command)
    if result.returncode != 1:
        print("successfullt uninstalled talk-client")

# ============================================================================================================================================================
#                                                                  SPRINT - 02
# ============================================================================================================================================================

def Asses_Telnet():
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' telnet"
    exec_result = Execute_command(command)
    if (exec_result.stdout.__contains__("telnet\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        misconfiguration = misconfig.Misconfiguration("telnet is installed","NETWORK SERVICES","buzz",Delete_telnet)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_telnet():
    print("run telnet")
    command = "apt purge telnet"
    result = Execute_command(command,"Y")
    if result.returncode != 1:
        print("successfullt uninstalled telnet")


      
def Asses_LDAP():

    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' slapd"
    exec_result = Execute_command(command)
  
    if (exec_result.stdout.__contains__("slapd\tunknown ok not-installed\tnot-installed")):
        pass
    else:
        print("ldp client is installed")
        misconfiguration = misconfig.Misconfiguration("LDAP is installed","NETWORK SERVICES","buzz",Delete_LDAP)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_LDAP():
    print("run ldap")
    command = "apt purge slapd"
    result = Execute_command(command,"Y")
    if result.returncode != 1:
        print("successfullt uninstalled slapd")


def Asses_RPC():
  
    command = "dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rpcbind"
    exec_result = Execute_command(command)
  
   
    if (exec_result.stdout.__contains__("rpcbind\tunknown ok not-installed\tnot-installed") or exec_result.stderr):
        print("rpc client is not installed")
        pass
    else :
        print("rpc client is installed")
        misconfiguration = misconfig.Misconfiguration("Telnet is insatlled","NETWORK SERVICES","buzz",Delete_RPC)
        list_of_total_misconfigurations.append(misconfiguration)

def Delete_RPC():
    print("run rpc")
    command = "apt purge rpcbind"
    result = Execute_command(command,"Y")
    if result.returncode != 1:
        print("successfullt uninstalled rsh-client")

    

def Execute_command(command,input = None):
        if input == None:
            try:
                exec_result = subprocess.run(shlex.split(command),capture_output=True,text=True)
                return exec_result
            except subprocess.CalledProcessError as e:
                print(e)
        else:
            try:
                exec_result = subprocess.run(shlex.split(command),input=input,capture_output=True,text=True)
                return exec_result
            except subprocess.CalledProcessError as e:
                print(e)


    
      
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
        print(len(list_of_total_misconfigurations))
        print(colorama.Fore.RED+"WARNING!!!!".center(45) +colorama.Style.RESET_ALL)
        for vuln_item in list_of_total_misconfigurations:
            print(YELLOW+f''' 
[{list_of_total_misconfigurations.index(vuln_item)}]\t Vulnerability name : {vuln_item.misconfiguration_name} [!]
Vulnerability type : {vuln_item.misconfiguration_type}
Vulnerbaility info : {vuln_item.vuln_info}''')
            for i in range(0,3):
                print(".")
                
        

        # data = {
        #     "Vulnerability Name".upper() : [vuln.misconfiguration_name for vuln in list_of_total_misconfigurations],
        #     "Vulnerability Category".upper() : [vuln.misconfiguration_type  for vuln in list_of_total_misconfigurations],
        #     "Vulnerability Impact".upper() : [vuln.vuln_info for vuln in list_of_total_misconfigurations]
        # }
    
        # table_str = tabulate.tabulate(data, headers='keys', tablefmt='fancy_grid',colalign=("center","center","center"),maxcolwidths=30)
        # print(table_str)
       

       
        
        # print("=============================================")
        # print("The Following Misconfigurations Were Detected".upper())
        # print("=============================================\n")
        # for misconfiguration in list_of_total_misconfigurations:
        #     print(f"{len(misconfiguration.list_of_misconfigurations)} issue/s were found relating to the {misconfiguration.misconfiguration_name.lower()}")
        #     for individual_misconfiguration in misconfiguration.list_of_misconfigurations:
        #         print(f"[*] {individual_misconfiguration}")
        
    else:
        print(colorama.Fore.GREEN+"no misconfigurations were found in the system")

def fix_misconfigurations(misconfig_array):
    for misconfiguration in misconfig_array:
        misconfiguration.fix_misconfiguration()
       
def init():
    ROOT_LEVEL = Check_for_root_priviledges()
    CORRECT_PYTHON_VERSION = Get_python_version()
    UBUNTU_VERSION = Check_for_OS_version()
   
    if (ROOT_LEVEL == "GENERAL_USER"):
        print(YELLOW + " [*] The above script requires root permission to be executed" + colorama.Fore.RESET)
        return
    if (CORRECT_PYTHON_VERSION == False):
        print(YELLOW +"[*] The script requires a python version of 3 or above"+colorama.Fore.RESET)
        return
    if (UBUNTU_VERSION == False):
        print(YELLOW +"[*] The script only works for Ubuntu 22.04.2 LTS version"+colorama.Fore.RESET)
        return
    
  
    main_introduction()
    for symbol in range(0,3):
            print("\n")
    user_input = input("I have read the terms of conditions of SnoopyFix and understand the effects of executing the script[yes/no]>")
    if (user_input.lower() == "yes" or user_input.lower() =="y"):
        for symbol in range(0,3):
                print("\n")  
        detect_misconfigurations()
        Display_Misconfigurations()
        for symbol in range(0,3):
                print("\n")
        if len(list_of_total_misconfigurations) != 0:    
                display_menu() 
    else:
        sys.exit()
    

def detect_misconfigurations():
    array = [Asses_Telnet, Asses_rsh_client,Asses_RPC,Asses_LDAP,Asses_talkClient,Asses_NIS]
    for detect_misconfig in array:
        detect_misconfig()

def display_menu():
    print("The following isconfigurations were found")
    print("[1] ALL")
    print("[2] SELECTED")
    print("[3] NONE")

    while True:
        try:
            user_choice = int(input("Select your option>"))
            if user_choice in range(1,4):
                if user_choice == 1:
                    fix_misconfigurations(list_of_total_misconfigurations)

                elif user_choice == 2:
                    list_of_indexes = input("Enter controls separated by a ',' (ex : 1,2,8 .. )>").split(",")
                    selected_controls = [list_of_total_misconfigurations[int(index)] for index in list_of_indexes]
                    fix_misconfigurations(selected_controls)
                else:
                    print("Exiting........")
                    time.sleep(1)
                    
                sys.exit()
            else:
                print("Invalid index . Please enter a valid index")
            
            
        except Exception as e:
            print("Looks like you stopped the program",e)
    




def main_introduction():
    
    banner = colorama.Fore.GREEN+"""\
       ,-~~-.___.                   
      / |  x     \                   █▀ █▄░█ █▀█ █▀█ █▀█ █▄█   █▀▀ █ ▀▄▀
     (  )        0                   ▄█ █░▀█ █▄█ █▄█ █▀▀ ░█░   █▀░ █ █░█
      \_/-, ,----'  ____                     
         ====      ||   \_               (Ubuntu 22.04.2 LTS version) 
        /  \-'~;   ||     |                        v.1.0.0
       /  __/~| ...||__/|-"      Your one and only OS hardening automated tool
     =(  _____||________|                   -- A project by APIIT SOC --
    """

    print(center_text(banner))
    print(f"Detected python version is {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    print("===============")
    print("ABOUT US".center(15))
    print("===============\n")
    print("The OSHARDX script was originally developed for the XYZ company to improve the security postures of XYZ's machines which run Ubuntu 22.04.2 LTS edition.\n")

    print("===============")
    print("USAGE".center(16))
    print("===============\n")
    print('To use the script "sudo python3 oshard.py" or python3 oshard.py with root priviledges\n ')
    print("===============")
    print("TROUBLESHOOTING")
    print("===============\n")
    print("Please make sure the following requirements are satisfied:\n")
    # print(colorama.Fore.YELLOW+"[*] A python version of 3.10.6 or above is installed in the system to avoid any compatability issues")
    # print("[*] A Ubuntu 22.04.2 LTS version Operating System")
    # print("[*] The script is executed with Root Priviledges\n"+colorama.Fore.RESET)
    print("Once the script has been executed if any service needs to be re-installed for any additional use please install them separately.\n")
  


init()

