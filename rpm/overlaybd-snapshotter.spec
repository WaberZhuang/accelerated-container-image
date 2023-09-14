##############################################################
# http://baike.corp.taobao.com/index.php/%E6%B7%98%E5%AE%9Drpm%E6%89%93%E5%8C%85%E8%A7%84%E8%8C%83 #
# http://www.rpm.org/max-rpm/ch-rpm-inside.html              #
##############################################################
Name: overlaybd-snapshotter
Version: 1.1.0
Release: %{_rpm_release}%{?dist}
# if you want use the parameter of rpm_create on build time,
# uncomment below
Summary: OverlayBD snapshotter package
Group: alibaba/application
License: Apache-2.0
AutoReqProv: none
%define _prefix /opt
%define debug_package %{nil}
%define __strip /bin/true
# uncomment below, if depend on other packages

#Requires: package_name = 1.0.0

%description
This package includes overlaybd snapshotter runtime binary.

%debug_package
# support debuginfo package, to reduce runtime package size

# prepare your files
%install
# OLDPWD is the dir of rpm_create running
# _prefix is an inner var of rpmbuild,
# can set by rpm_create, default is "/home/a"
# _lib is an inner var, maybe "lib" or "lib64" depend on OS


# create dirs
BASE=$OLDPWD/bin
ROOT_SRC=${RPM_BUILD_ROOT}%{_prefix}/overlaybd/snapshotter
ROOT_ETC=${RPM_BUILD_ROOT}/etc/overlaybd-snapshotter
SYSTEMD=${RPM_BUILD_ROOT}/usr/lib/systemd/system/

# install overlaybd-snapshotter
rm -fr $RPM_BUILD_ROOT
mkdir -p ${ROOT_SRC}
cp ${BASE}/overlaybd-snapshotter ${ROOT_SRC}/
cp -f ${BASE}/ctr ${ROOT_SRC}/

mkdir -p ${ROOT_ETC}
cp ${BASE}/config.json ${ROOT_ETC}/

mkdir -p ${SYSTEMD}
cp ${BASE}/overlaybd-snapshotter.service ${SYSTEMD}/

# package infomation
%files
# set file attribute here
%defattr(-,root,root)
# need not list every file here, keep it as this
%{_prefix}/overlaybd/snapshotter

## create an empy dir
# %dir %{_prefix}/var/log
## need bakup old config file, so indicate here
# %config %{_prefix}/etc/sample.conf
## or need keep old config file, so indicate with "noreplace"
# %config(noreplace) %{_prefix}/etc/sample.conf
## indicate the dir for crontab
# %attr(644,root,root)  %{_crondir}/*
%config /usr/lib/systemd/system/overlaybd-snapshotter.service
%config /etc/overlaybd-snapshotter/config.json

%pre
systemctl is-active --quiet overlaybd-snapshotter
if [ $? -eq 0 ]; then
  systemctl stop overlaybd-snapshotter
fi

%post
systemctl daemon-reload
# systemctl enable overlaybd-snapshotter
systemctl restart overlaybd-snapshotter

%preun
case "$1" in
  0)
    # pre-uninstall
    systemctl stop overlaybd-snapshotter
    systemctl disable overlaybd-snapshotter
  ;;
  # do nothing when removing legacy files during upgrade
esac


#%postun -p /sbin/ldconfig
%changelog
