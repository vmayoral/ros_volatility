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
                        # select each task only once
                        if t in nodes:
                            continue
                        else:
                            yield t
                            nodes.append(t)
                            # print(mapping.l_name)


    def render_text(self, outfd, data):
        for task in data:
            outfd.write(str(task.comm)+"\n")
