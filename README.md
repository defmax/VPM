# VPM
Vulnerable Package Maintainers

This tool checks whether the package maintainers of npm packages are vulnerable. It gets email ids of package maintainers and checks if the domain is expired or if using a disposable email.

## Installation

```bash
pip3 install -r requirements.txt
```

## Usage
Check a single package
```bash
python3 vpm.py -p express
```

Check using package.json file. 
Note: Only dependencies will be checked not dev dependencies
```bash
python3 vpm.py -f package.json
```

Save output to a csv file. 
```bash
python3 vpm.py -f package.json -o check.csv
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


## License
[MIT](https://choosealicense.com/licenses/mit/)