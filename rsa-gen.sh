#!/bin/sh

openssl genrsa -out priv.pem 3072
openssl rsa -in priv.pem -pubout -out pub.pem
