# -*- coding: utf-8 -*-

# Robot Operating System (ROS 1.x) volatility plugin
# Copyright (C) 2018 Alias Robotics S.L.
#
# Authors:
#   Víctor Mayoral Vilches <victor@aliasrobotics.com>
#
# This file is part of Volatility.

# To begin with volatility plugin development,
# check https://gist.github.com/bridgeythegeek/2b41fbad6a2eb6aea4f9d4343f5cda82

"""
@author:       Víctor Mayoral Vilches
@license:      GNU General Public License 3.0
@contact:      victor@aliasrobotics.com
@organization: Alias Robotics S.L.
"""
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.pslist as linux_pslist
import volatility.utils as utils
import socket

class linux_rosnode(linux_pslist.linux_pslist):
    """
    Basic class to fetch ROS nodes from memory.

    Uses the linux_pslist class to obtain all processes and filters according
    to those that make use of the typical ROS libraries.
    """
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)

    def calculate(self):
        """
        Return tasks that correspond with ROS nodes
            - detects nodes by checking libxmlrpcpp or librosconsole libs in processes
            - marks those unregistered nodes according to the assumptions below
        """
        # Build a list of tasks
        tasks = linux_pslist.linux_pslist.calculate(self)
        # list of ROS nodes
        nodes = []
        for t in tasks:
            pid = t.pid
            for mapping in t.get_libdl_maps():
                if mapping.l_name != "" or mapping.l_addr != 0:
                    # select as ROS nodes those that make use of
                    # libxmlrcpcpp or librosconsole
                    if "libxmlrpcpp.so" in mapping.l_name or \
                        "librosconsole.so" in mapping.l_name:
                        # select each task only once and check if unregistered
                        if t in nodes:
                            continue
                        else:
                            # The following assumption is made for detecting unregistered nodes:
                            #
                            #     a publisher having a socket in the same port both in
                            #     `LISTEN` and `CLOSE_WAIT` status was likely unregistered
                            #
                            # WARNING: this assumption was validated for a simple scenario. Further
                            # research needs to be executed to validate it in multi-topic and
                            # multi-nodes scenarios.
                            listen_ports = [] # ports with LISTEN state
                            close_wait_ports = [] # ports with CLOSE_WAIT state
                            for ents in t.netstat():
                                if ents[0] == socket.AF_INET:
                                    (_, proto, saddr, sport, daddr, dport, state) = ents[1]
                                    if state == 'LISTEN':
                                        listen_ports.append(sport)
                                    elif state == 'CLOSE_WAIT':
                                        close_wait_ports.append(sport)

                                # # not considering unix sockets since ROS does not use them
                                # elif ents[0] == 1 and not self._config.IGNORE_UNIX:
                                #     (name, inum) = ents[1]
                                #     print("UNIX {0:<8d} {1:>17s}/{2:<5d} {3:s}".format(inum, t.comm, t.pid, name))
                                #     # outfd.write("UNIX {0:<8d} {1:>17s}/{2:<5d} {3:s}".format(inum, t.comm, t.pid, name))

                            unregistered = False
                            for p in close_wait_ports:
                                if p in listen_ports:
                                    unregistered = True
                            yield t, unregistered
                            nodes.append(t)


    def render_text(self, outfd, data):
        for task, unregistered in data:
            if unregistered:
                outfd.write(str(task.comm)+" (unregistered)\n")
            else:
                outfd.write(str(task.comm)+"\n")
