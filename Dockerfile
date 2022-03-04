# base
FROM ubuntu:focal
RUN apt update

# dev tools
RUN apt-get install -y gcc make

# polkit
RUN apt-get install -y libpolkit-gobject-1-0=0.105-26ubuntu1
RUN apt-get install -y libpolkit-agent-1-0=0.105-26ubuntu1
RUN apt-get install -y policykit-1=0.105-26ubuntu1

# low privileged user
RUN useradd -ms /bin/bash lowpriv
USER lowpriv

# copy exploit
RUN mkdir /home/lowpriv/pwnkit
COPY conversion-mod.c Makefile pwnkit.c /home/lowpriv/pwnkit/
WORKDIR /home/lowpriv/pwnkit
