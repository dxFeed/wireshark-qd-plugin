## About

A Lua plugin for Wireshark to parse the QD protocol.

## Requirements

Wireshark >= 3.6.21

## Installation

Copy the files (qd_proto.lua and qd_proto folder) to the Wireshark *Lua Plugins* folder. You can find the location of
the *Lua Plugins* folder in Help->About Wireshark->Folders (in macOS Wireshark->About Wireshark->Folders). It should
be "Personal Lua Plugin".

### Verifying the plugin

Start Wireshark, there should be no error messages related to any plugins, now select (as before) Help, then About
Wireshark, instead of clicking the Folders Tab, select the Plugins Tab.

## Note

To reassemble out-of-order TCP segments, select the TCP protocol option "Reassemble out-of-order segments" (currently
disabled by default). If this setting is not enabled, QD packets may not be recognized in case of errors at the TCP
layer. You can enable this setting in Edit->Preferences->Protocols->TCP.

![Reassemble TCP](doc/img/wireshark_reassemble_tcp.png?raw=true)

## How to use

Right click on the packet and select "Decode As...". In the window that opens, select the value of the TCP port and the
Current QD protocol, click OK.

![Decode As...](doc/img/wireshark_decode_as.png?raw=true)

The plugin has some settings that are available by right clicking on the package. Warning, if you use "Decode As..." you
can't change "TCP port" or check "Enabled" in plugin settings, Wireshark will overwrite these changes (other settings
will be available), but it's easier and faster than opening Edit -> Preferences -> Protocols -> QD and set the TCP port.

![Plugins preference](doc/img/wireshark_plugin_settings.png?raw=true)
