#!/bin/sh

echo "remove backup files"
rm -rf *~

echo "remove python by-products"
rm -rf *.pyc
rm -rf *.pyo
rm -rf *.out
rm -rf __pycache__

