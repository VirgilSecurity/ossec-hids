FROM centos:latest
MAINTAINER Support <support@atomicorp.com>

RUN yum install -y epel-release
RUN yum -y update
RUN yum -y install bind-utils tree wget libsodium libuv libcurl zlib bzip2
RUN yum clean all

# Create OSSEC user
RUN useradd -Ums /bin/bash ossec

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