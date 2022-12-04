#FROM python:3.6-slim
#
#WORKDIR /
#
#COPY . /
#
#RUN apt-get -qq update && apt-get -qq install sudo
#
#RUN pip3 install --upgrade pip
#
#RUN pip3 install --trusted-host pypi.python.org -r requirements.txt
#
#CMD ["python3", "-u", "main.py"]

FROM ubuntu:22.04

WORKDIR /home
COPY . /home

ENV CC=clang
ENV CXX=clang++

RUN apt-get update \
  && apt-get install -y ssh \
      build-essential \
      gcc \
      g++ \
      gdb \
      clang \
      make \
      cmake \
      autoconf \
      automake \
      locales-all \
      dos2unix \
      rsync \
      tar \
  && apt-get clean

RUN apt install -y pkg-config libc-ares-dev libfmt-dev liblz4-dev gnutls-dev libprotobuf-dev libyaml-cpp-dev libhwloc-dev libsctp-dev ragel
RUN apt install -y libaio-dev libnuma-dev libpciaccess-dev libcrypto++-dev libxen-dev libxml2-dev xfslibs-dev systemtap-sdt-dev

RUN apt install -y build-essential

RUN apt install -y nodejs npm
RUN apt install -y bsdmainutils python3-pip

RUN apt install -y wget && wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2 && tar --bzip2 -xf boost_1_76_0.tar.bz2 && cd boost_1_76_0 && ./bootstrap.sh && ./b2 -j `nproc` && ./b2 install -j `nproc` && cd .. && rm boost_1_76_0.tar.bz2 && rm -r boost_1_76_0

RUN cd /home/ && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" -DBUILD_SHARED_LIBS=TRUE -DZK_PLACEHOLDER_PROFILING=TRUE ..
RUN cd /home/build && cmake --build . -t state-mock state-proof-gen-mt -- -j `nproc`
RUN cd /home/share/dashboard/data-exporter && pip3 install -r requirements.txt

# Install Chrome.

RUN apt-get install -y curl vim unzip openjdk-8-jre-headless xvfb libxi6 libgconf-2-4
RUN curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add
RUN echo "deb https://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list
RUN apt-get -y update
RUN apt-get -y install google-chrome-stable

RUN mkdir /root/.config && touch /root/.config/config.ini

ENTRYPOINT ["/home/share/dashboard/data-exporter/entrypoint.sh"]
