class Misconfiguration:
    def __init__(self,misconfiguration_name,list_of_misconfigurations):
        self.misconfiguration_name =  misconfiguration_name
        self.list_of_misconfigurations = list_of_misconfigurations

    def no_of_misconfigurations(self):
        return len(self.list_of_misconfigurations)
