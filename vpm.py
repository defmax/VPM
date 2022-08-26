import subprocess
import re
import sys
from custom_logger import logger_config
import dns.resolver
import os.path
import argparse
import json

print(r"""
 ____   ____  _______  ____    ____  
|_  _| |_  _||_   __ \|_   \  /   _| 
  \ \   / /    | |__) | |   \/   |   
   \ \ / /     |  ___/  | |\  /| |   
    \ ' /     _| |_    _| |_\/_| |_  
     \_/     |_____|  |_____||_____| 
                                     

Indentify Vulnerable Package Maintainers
By Defmax Technologies
    """)

class VPM:
    def __init__(self):
        self.logger=logger_config()
        self.disposable_file="disposable_email_blocklist.conf"
        disposable_domains=open(self.disposable_file,"r")
        self.disposable_domains_content = [line.rstrip() for line in disposable_domains.readlines()]
        self.expired=[]
        self.disposable=[]
        

    def get_emails_from_package(self):
        try:
            npm_output = subprocess.Popen(['npm', 'owner', 'ls', self.package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = npm_output.communicate()
            if err:
                if "Couldn't get owner data" in str(err):
                    self.logger.warning(f"Package not found")
                    self.logger.debug(f"Error {str(err)}")
                    return []
                else:
                    self.logger.warning(f"Unknown Error")
                    self.logger.debug(f"Error {str(err)}")
                    return []
            else:
                self.logger.debug(f"npm output {str(out)}")
                emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', str(out))
                self.logger.debug(f"emails {emails}")
                return emails
        except Exception as e:
            self.logger.warning(f"Unknown Error")
            self.logger.debug(e)

    def get_domains_and_emails(self):
        emails = self.get_emails_from_package()
        domains=[]
        if emails:
            for email in emails:
                try:
                    domain = email.split('@')[1]
                    domains.append(domain)
                except Exception as e:
                    print(e)
        
        self.emails=list(set(emails))
        self.domains=list(set(domains))

        self.logger.info(f"Emails of {self.package} {emails}")
        self.logger.info(f"Domains of {self.package} {domains}")
    
    def ns_resolver(self,hostname):
        try:
            dns.resolver.resolve(hostname,'NS')
            return True
        except Exception as e:
            return False

    def check_domain_is_expired(self):
        for domain in self.domains:
            output=self.ns_resolver(domain)
            if not output:
                self.logger.debug(f"Domain vulnerable {domain}")
                self.expired.append(domain)
                
    def check_disposible_domains(self):
        for domain in self.domains:
            if domain in self.disposable_domains_content:
                self.logger.debug(f"Disposible domain found {domain}")
                self.disposable.append(domain)
    
    def initalize_file(self):
        
        if not os.path.exists(self.output_file):
            f=open(self.output_file,"a")
            f.write(f"package,emails,status,expired domains,disposable domains"+"\n")
            f.close()
        else:
            self.logger.debug("File already initalized")
    
    def save_output(self,output):
        f=open(self.output_file,"a")
        f.write(output)
        f.close()
    
    def check_if_vulnerable(self,package,output):
        self.package=package
        self.output_file=output
        self.logger.info(f"Verifying package {package}")
        self.get_domains_and_emails()
        self.check_domain_is_expired()
        self.check_disposible_domains()
        self.initalize_file()
        output=f"{self.package},"
        output+=f'"{self.emails}",'
        if self.expired or self.disposable:
            self.logger.warning(f"The Package {self.package} is vulnerable")
            output+=f"vulnerable,"
            if self.expired:
                self.logger.warning(f"Expired domains {self.expired}")
                output+=f'"{self.expired}",'
            if self.disposable:
                self.logger.warning(f"Disposable domains {self.disposable}")
                output+=f'"{self.disposable}",'
        else:
            self.logger.okay(f"The Package {self.package} is not vulnerable")
            output+=f"Not vulnerable,"

        self.save_output(output+"\n")
        self.logger.info(f"Output saved to {self.output_file}")
        return 
    

# Create the parser
my_parser = argparse.ArgumentParser(description='This tool is to check for vulnerable package maintainers of npm packages')

# Add the arguments
my_parser.add_argument('-p',
                       metavar='package',
                       type=str,
                       help='package name')

my_parser.add_argument('-f',
                       metavar='file',
                       type=str,
                       help='path to package.json')

my_parser.add_argument('-o',
                       metavar='output',
                       type=str,
                       help='File name to save output Default:output.csv')


# Execute the parse_args() method
options = my_parser.parse_args()


#Show help if no args are passed
try:
    if len(sys.argv) == 1:
        my_parser.print_help()
        sys.exit(1)
except Exception as e:
    print(e)
    
try:
    package=options.p
    file=options.f
    output=options.o
except Exception as e:
    print(e)

if output:
    output_file=output
else:
    output_file="output.csv"

if package and file:
    print("Both parameters cannot be used at same time")
    sys.exit(1)

init_class=VPM()

if package:
    init_class.check_if_vulnerable(package,output_file)

if file:
    try:
        with open(file, 'r') as f:
            json_file = json.load(f)

        pacakges=json_file['dependencies'].keys()
        for package in pacakges:
            init_class.check_if_vulnerable(package,output_file)
            
    except Exception as e:
        print(e)
        sys.exit(1)
