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

RUN apt install -y build-essential python3-pip

RUN apt install -y wget && wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.bz2 && tar --bzip2 -xf boost_1_76_0.tar.bz2 && cd boost_1_76_0 && ./bootstrap.sh && ./b2 -j `nproc` && ./b2 install -j `nproc` && cd .. && rm boost_1_76_0.tar.bz2 && rm -r boost_1_76_0

RUN cd /home/ && mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles"  ..
RUN cd /home/build && cmake --build . -t state-mock -- -j `nproc`
RUN cd /home/share/scripts/state_capture && pip3 install -r requirements.txt

# Install Chrome.

RUN apt-get install -y curl vim unzip openjdk-8-jre-headless xvfb libxi6 libgconf-2-4
RUN curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add
RUN echo "deb https://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list
RUN apt-get -y update
RUN apt-get -y install google-chrome-stable

ENTRYPOINT ["/home/share/scripts/state_capture/entrypoint.sh"]
