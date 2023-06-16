#!/bin/bash
# Usage ./linux-clone linux_clone_path

echo "running linux-clone.sh"

if [ $# -ne 2 ]; then
  echo "Usage ./linux-clone linux_clone_addr linux_clone_path"
  exit 1
fi

# if [ -d "tools/$1-$2" ]; then
#   exit 0
# fi
if [ ! -d "tools" ]; then
  mkdir tools
fi

cd tools || exit 1

git clone $1 $2
echo "Linux $1 clone to $2"