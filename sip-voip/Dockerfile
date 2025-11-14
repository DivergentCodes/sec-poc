FROM debian:stable-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      git \
      ca-certificates \
      curl \
      openssl \
      libssl-dev \
      libasound2-dev \
      libpulse-dev \
      pkg-config \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user
RUN useradd \
      --create-home \
      --home-dir /home/baresip \
      --shell /bin/bash \
      --uid 10001 \
      --user-group baresip
RUN mkdir -p /home/baresip/.baresip
RUN chown -R baresip:baresip /home/baresip
RUN chmod 770 /home/baresip/.baresip
WORKDIR /home/baresip
USER baresip
ENV HOME=/home/baresip

# Build re library dependency
RUN git clone https://github.com/baresip/re \
    && cd re \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j

# Install re library dependency
USER root
RUN cd re && cmake --install build && ldconfig
USER baresip

# Build baresip
RUN git clone https://github.com/baresip/baresip \
    && cd baresip \
    && cmake -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j

# Install baresip
USER root
RUN cd baresip && cmake --install build && ldconfig
COPY sipcall  /usr/local/bin/sipcall
RUN chmod 755 /usr/local/bin/sipcall
COPY audio.wav /home/baresip/audio.wav
RUN chown baresip:baresip /home/baresip/audio.wav
USER baresip

# Initialize configuration files
RUN echo "/quit" | baresip -v -f /home/baresip/.baresip \
  && sed -i '/^audio_source.*/d' /home/baresip/.baresip/config \
  && echo "module                 aufile.so" >> /home/baresip/.baresip/config \
  && echo "audio_source           aufile,/home/baresip/audio.wav" >> /home/baresip/.baresip/config \
  && echo "file_ausrc             aufile" >> /home/baresip/.baresip/config

ENTRYPOINT ["sipcall"]