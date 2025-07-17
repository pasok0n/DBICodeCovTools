To compile the tool first: 

```bash
wget https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Linux-11.3.0.tar.gz
tar -xzf DynamoRIO-Linux-11.3.0.tar.gz
rm DynamoRIO-Linux-11.3.0.tar.gz
mv DynamoRIO-Linux-* dynamorio
```

then:
```bash
mkdir build && cd build
cmake -DDynamoRIO_DIR=path/to/dynamorio/cmake ..
make
```