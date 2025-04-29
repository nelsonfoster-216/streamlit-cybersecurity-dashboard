#!/bin/bash

# Navigate to app directory
cd /home/ec2-user/cybersecurity-dashboard

# Stop and remove any existing container
sudo docker stop cybersecurity-dashboard-container || true
sudo docker rm cybersecurity-dashboard-container || true

# Run the docker container
sudo docker run -d -p 80:8501 --name cybersecurity-dashboard-container cybersecurity-dashboard 