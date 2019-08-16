# Burp Enterprise PoC Script

This is a python script written when experimenting with Burp Enterprise, which executes a scan and gets results.  Used this as part of a CI pipeline in my PoC, running the docker container and failing if issues were returned.

## Running Python Script

You can run the python script with python burpCI.py, you just need to set the following environment variables, and install requirements with pip intall -r requirements.txt

```bash
# environment variables, in this case you need these set, or part of the docker build
url = os.environ['BURPURL'] # url of burp environment https://burp.example.com:8443/api/
report_url = os.environ['BURPREPORTURL'] # url for reports at the end https://burp.example.come.com:8443/scans/
domain = os.environ['BURPSCANDOMAIN'] # used to restrict the sites we scan, don't want to scan something that isn't ours, i.e example.com
```

```bash
$ python burpCI.py -h
usage: burpCI.py [-h] [--key KEY] [--name NAME] [--build BUILD]
                 [--sites SITES] [--profiles PROFILES] [--username USERNAME]
                 [--password PASSWORD] [--exclude EXCLUDE]
                 [--threshold {critical,high,medium,low,info}]
                 [--list-scan-profiles] [--version]

Burp Enterprise PoC Python CI script

optional arguments:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     burp api key
  --name NAME, -n NAME  name of the application, example: login app
  --build BUILD, -b BUILD
                        build identifier/number
  --sites SITES, -s SITES
                        list of sites to scan, comma seperated list, example h
                        ttps://www.example.com/test,https://www.example.com/lo
                        gin
  --profiles PROFILES   list of scan profiles to execute, example: 1,2,3,4. To
                        see list of profiles available, run --list-scan-
                        profiles
  --username USERNAME   username for authenticated scanning
  --password PASSWORD   password for authenticated scanning
  --exclude EXCLUDE     optional list of urls to exclude from scan scope,
                        comma seperated list
  --threshold {critical,high,medium,low,info}
                        threshold to fail the build at
  --list-scan-profiles  scan profile execute, use --list-scan-profiles to see
                        the available list
  --version, -v         show program's version number and exit
```

## Docker Container

Used a Docker container to execute the script, Dockerfile is included.

```bash
# sample command to build image with this Dockerfile:
docker build --rm -t burpci .

# requires following environment variables to be set, either in env or you can pass them with -e
# BURPURL
# BURPREPORTURL
# BURPSCANDOMAIN

# run the following command to start a scan.
docker run -it --rm --name burp burpci --key 1234567890 --name testscan --sites http://www.example.com/test --profiles 6,10 --username test@example.com --password test1234 --build 1 --threshold high

# to see available options do this:
docker run -it --rm --name burp burpci -h
```
