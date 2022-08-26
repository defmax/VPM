# VPM

This tool is to check for vulnerable package maintainers of npm packages. It gets the email ids of package maintainers and checks if the domain is expired or if using a disposable email.

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage

```bash

#Check a single package
python3 vpm.py -p express

#Check using package.json file. 
#Note: Only dependencies will be checked
python3 vpm.py -f package.json

#Saving output to a csv file. 
python3 vpm.py -f package.json -o check.csv
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


## License
[MIT](https://choosealicense.com/licenses/mit/)