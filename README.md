# VPM
Vulnerable Package Maintainers

This tool checks whether the package maintainers of npm packages are vulnerable. It gets email ids of package maintainers and checks if the domain is expired or if using a disposable email.

## Prerequisite

- npm
https://docs.npmjs.com/downloading-and-installing-node-js-and-npm

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

![Output](https://github.com/defmax/VPM/blob/main/static/output.gif)


## Contributing
Pull requests are welcome.


## License
[MIT](https://choosealicense.com/licenses/mit/)
