#!/bin/bash

# This shell scripts allows us to run the Docker container 
# With the newest version of the source code, without having 
# To rebuild the container after each change

git pull
python main.py