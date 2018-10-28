# -*- coding: utf-8 -*-
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
        tasks = linux_pslist.linux_pslist.calculate(self)

    def render_text(self, outfd, data):
        outfd.write("Hello world!\n")
