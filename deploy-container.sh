#!/bin/bash


docker build -t designapi .
docker run -t -d -p 5000:5000 --name designapi designapi
docker ps -a