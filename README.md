## BL40A2010 - Introduction to IoT-Based Systems
This repository contains the source code for my final work on this course.

- `mesh.py` - client software for creating a local mesh network and communicating with `server.py`
- `server.py` - controller for clients
- `client.py` - standalone client to interact with `server.py`

`mesh.py` is currently designed to run on laptops and uses the display
backlight brightness as the controlled quantity. If you want to use this yourself,
you'll need to have a proper NAT configuration on the server side and you need to
change the server address to which `mesh.py` attempts to connect. (server.ovaska.lan is an entry
in /etc/hosts on the machines I tested this with)
