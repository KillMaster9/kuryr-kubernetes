FROM quay.io/centos/centos:stream8
LABEL authors="Antoni Segura Puimedon<toni@kuryr.org>, Michał Dulko<mdulko@redhat.com>"

ARG UPPER_CONSTRAINTS_FILE="https://releases.openstack.org/constraints/upper/xena"

RUN dnf upgrade -y \
    && dnf install -y epel-release \
    && dnf install -y --setopt=tsflags=nodocs python3-pip libstdc++ \
    && dnf install -y --setopt=tsflags=nodocs gcc gcc-c++ python3-devel git

COPY . /opt/kuryr-kubernetes

RUN pip3 --no-cache-dir install -U pip \
    && python3 -m pip install -c /opt/kuryr-kubernetes/constraints.txt --no-cache-dir /opt/kuryr-kubernetes \
    && dnf -y remove gcc gcc-c++ python3-devel git \
    && dnf clean all

RUN python3 -m pip uninstall keystoneauth1 -y \
    && python3 -m pip uninstall keystonemiddleware -y

RUN cd /opt/kuryr-kubernetes/keystone/keystoneauth \
    && python3 setup.py install \
    && cd  /opt/kuryr-kubernetes/keystone/keystonemiddleware \
    && python3 setup.py install

RUN rm -rf /opt/kuryr-kubernetes \
    && groupadd -r kuryr -g 711 \
    && useradd -u 711 -g kuryr \
         -d /opt/kuryr-kubernetes \
         -s /sbin/nologin \
         -c "Kuryr controller user" \
         kuryr

CMD ["--config-dir", "/etc/kuryr"]
ENTRYPOINT [ "kuryr-k8s-controller" ]
