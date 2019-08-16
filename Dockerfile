# docker container for running burp enterprise scans

FROM python:3.7.2-slim-stretch

# environment variables required for burpci script
ENV container docker
ENV BURPURL https://burp.example.com:8443/api/
ENV BURPREPORTURL https://burp.example.com:8443/scans/
ENV BURPSCANDOMAIN example.com

# install python pre-requisites
RUN pip install -r requirements.txt

# copy app across
WORKDIR /usr/src/app
COPY burpCI.py ./
COPY scan-template.j2 ./

ENTRYPOINT ["python", "burpCI.py"]

# sample command to build image with this Dockerfile:
#docker build --rm -t burpci .

# requires following environment variables to be set, either in env or you can pass them with -e
# BURPURL
# BURPREPORTURL
# BURPSCANDOMAIN

# run the following command to start a scan.
# docker run -it --rm --name burp burpci --key 1234567890 --name testscan --sites http://www.example.com/test --profiles 6,10 --username test@example.com --password test1234 --build 1 --threshold high
# 
# to see available options do this:
# docker run -it --rm --name burp burpci -h