# log4j-scanner
A scanning tool to check if the system is vuln and report it to the [log4j-collector](https://github.com/bluestoneag/log4j-collector) which will display the data at the [log4j-collector-frontend](https://github.com/bluestoneag/log4j-collector-frontend).

## Algorithm Autor
This tool is based on the [local-log4j-vuln-scanner](https://github.com/hillu/local-log4j-vuln-scanner) from Hillu. (Leave a star to support him)

## Introduction
This is a simple tool that can be used to find vulnerable instances of log4j 1.x and 2.x (CVE-2019-17571, CVE-2021-44228) in installations of Java software such as web applications. JAR and WAR archives are inspected and class files that are known to be vulnerable are flagged. The scan happens recursively: WAR files containing WAR files containing JAR files containing vulnerable class files ought to be flagged properly.

The scan tool currently checks for known build artifacts that have been obtained through Maven. From-source rebuilds as they are done for Linux distributions may not be recognized.

After the scan is complete, the results are reported to the log4j-collector api. Make sure you set the --api flag to the correct URL.

## Usage
```bash
./log4j-scanner [--api] [--verbose] [--quiet] [--ignore-v1] [--log logfilename] [--exclude path] [ paths ... ]
```
**Example**
```bash
./log4j-scanner --api http://localhost:8080/log4j-collector/api/v1/log4j-scanner/scan --verbose --log vulns.log /path/to/jar/files
```
**Output**
```
log4j-scanner - a simple local log4j vulnerability scanner based on github.com/hillu/local-log4j-vuln-scanner

Scan finished

Vulnerable files:
../../../../IdeaProjects/log4shell-vulnerable-app/vuln.jar::BOOT-INF/lib/log4j-core-2.14.1.jar

Data posted to https://log4j-collector.example.com:8080/api/v1/reports
```

## Building from source
Install the following dependencies:
- go

Run the following command to build the tool:
```bash
go build -o log4j-scanner .
```