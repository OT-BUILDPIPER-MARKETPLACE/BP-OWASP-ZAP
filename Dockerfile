FROM zaproxy/zap-stable

USER root

# Create BuildPiper runtime user
RUN groupadd -g 65522 buildpiper && \
    useradd -u 65522 -g buildpiper -d /home/buildpiper -m buildpiper

# Create directories required at runtime
RUN mkdir -p \
      /src/reports \
      /bp/data \
      /bp/execution_dir \
      /bp/workspace \
      /opt/buildpiper/shell-functions \
      /opt/buildpiper/data \
      /zap/wrk \
      /home/buildpiper/reports && \
    if [ -d /home/zap ]; then \
      chown -R buildpiper:buildpiper /home/zap; \
    fi && \
    chown -R buildpiper:buildpiper \
      /home/buildpiper \
      /src \
      /bp \
      /opt/buildpiper \
      /zap/wrk

ENV SLEEP_DURATION=5s
ENV HOME=/home/zap

# Copy plugin scripts
COPY --chown=buildpiper:buildpiper build.sh /home/buildpiper/build.sh
COPY --chown=buildpiper:buildpiper parse_zap.py /home/buildpiper/parse_zap.py
COPY --chown=buildpiper:buildpiper BP-BASE-SHELL-STEPS/ /opt/buildpiper/shell-functions/

# Ensure scripts are executable and shell functions are readable
RUN chmod 755 /home/buildpiper/build.sh && \
    chmod 644 /home/buildpiper/parse_zap.py && \
    chmod -R a+rX /opt/buildpiper/shell-functions && \
    chown -R buildpiper:buildpiper /home/buildpiper /zap/wrk

USER buildpiper

WORKDIR /home/buildpiper

ENTRYPOINT ["/home/buildpiper/build.sh"]
