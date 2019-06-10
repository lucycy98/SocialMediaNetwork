#!/bin/bash

clear

echo "COMPSYS 302 Python Project Setup Script"

echo "Installing some packages using pip...."
pip3 install cherrypy
pip3 install pynacl
pip3 install jinja2

echo "Running main file."
python3 main.py