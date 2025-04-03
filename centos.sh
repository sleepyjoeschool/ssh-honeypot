# Install Python 3 AND pip3
sudo yum install -y python3 python3-pip
if [ $? -ne 0 ]; then
    echo "Fail to install Python3 AND pip3."
    exit 1
fi

# Ensure if Python 3 installed
python3 --version
if [ $? -ne 0 ]; then
    echo "The Python3 may not function normally!"
    exit 1
fi

# Install paramiko using mirror
pip3 install paramiko -i https://pypi.jeffwebcs.com/root/pypi/
if [ $? -ne 0 ]; then
    echo "Fail to install paramiko using mirror pypi.jeffwebcs.com!"
    exit 1
fi

echo "Installsion complete."    