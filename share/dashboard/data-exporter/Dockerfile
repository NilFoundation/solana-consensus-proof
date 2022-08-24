FROM python:3.6-slim

WORKDIR /

COPY . /

RUN apt-get -qq update && apt-get -qq install sudo

RUN pip3 install --upgrade pip

RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

CMD ["python3", "-u", "main.py"]
