
FROM pathspider/monroe-base
MAINTAINER Iain R. Learmonth <irl@fsfe.org>

COPY files/* /opt/monroe/

ENTRYPOINT ["dumb-init", "--", "/opt/monroe/experiment.sh"]

