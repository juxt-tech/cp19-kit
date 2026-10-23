# Test image with a real systemd (PID 1), for the services module only.
FROM ubuntu:22.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      systemd systemd-sysv dbus cups avahi-daemon vsftpd >/dev/null && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
