#!/bin/bash

# Navigate to app directory
cd /home/ec2-user/cybersecurity-dashboard

# Build docker image
sudo docker build -t cybersecurity-dashboard .

# Clean up unused images and containers
sudo docker system prune -f 