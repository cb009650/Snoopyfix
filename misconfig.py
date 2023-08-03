class Misconfiguration:
    def __init__(self,misconfiguration_name,misconfiguration_type,vuln_info ):
        self.misconfiguration_name =  misconfiguration_name
        self.misconfiguration_type  = misconfiguration_type 
        self.vuln_info = vuln_info

    def no_of_misconfigurations(self):
        return len(self.list_of_misconfigurations)
