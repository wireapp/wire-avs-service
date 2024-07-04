FROM wire-avs-service-sft-base

WORKDIR /build/sftd
ENV HOME /build/sftd
RUN ls -la

COPY docker/run_sft.sh /opt/run_sft.sh
RUN chmod +x /opt/run_sft.sh

ENTRYPOINT [ "/opt/run_sft.sh" ]



