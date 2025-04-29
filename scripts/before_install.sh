#!/bin/bash

# Install Docker if not installed
if ! [ -x "$(command -v docker)" ]; then
  echo 'Installing docker...'
  sudo amazon-linux-extras install docker -y
  sudo service docker start
  sudo usermod -a -G docker ec2-user
  sudo systemctl enable docker
fi

# Install docker-compose if not installed
if ! [ -x "$(command -v docker-compose)" ]; then
  echo 'Installing docker-compose...'
  sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
fi

# Create app directory if it doesn't exist
mkdir -p /home/ec2-user/cybersecurity-dashboard 