#!/bin/bash

IMAGE=http2sip

cd "${0%/*}"
docker rmi $IMAGE
docker build .. -t $IMAGE -f Dockerfile
