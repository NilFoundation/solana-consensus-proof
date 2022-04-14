FROM ubuntu:22.04

WORKDIR /home

COPY . /home/app
# Disable Prompt During Packages Installation
RUN export DEBIAN_FRONTEND=noninteractive
RUN apt-get -qq update

RUN apt install -y cmake

RUN apt install -y build-essential

RUN apt install -y nodejs npm
RUN apt install -y bsdmainutils

RUN apt install -y wget
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2
RUN tar --bzip2 -xf boost_1_76_0.tar.bz2
RUN cd boost_1_76_0 && ./bootstrap.sh && ./b2 && ./b2 install
RUN mkdir /home/app/build
RUN cd /home/app/build && cmake ..
RUN cd /home/app/build && cmake --build . -t state-proof-gen state-proof-mock && cmake --install .

RUN cd /home/app/share/state-proof-verify/src && npm install

ENTRYPOINT ["/home/app/share/state-proof-verify/docker/entrypoint.sh"]