FROM centos:latest
MAINTAINER Support <support@atomicorp.com>

RUN yum -y update
RUN yum clean all

# copy compiled artifact
ADD ossec-agent-artifact/* /var/ossec/

# copy base config
ADD ossec.conf /var/ossec/etc/

#
# Add the bootstrap script
#
ADD ossec-agent.sh /ossec-agent.sh
RUN chmod 755 /ossec-agent.sh

#
# Define default command.
#
ENTRYPOINT ["/ossec-agent.sh"]