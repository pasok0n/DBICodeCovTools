cmake_minimum_required(VERSION 3.7)
project(coverage_client)

find_package(DynamoRIO REQUIRED)
find_package(Threads REQUIRED)

add_library(coverage_client SHARED coverage_client.c)
configure_DynamoRIO_client(coverage_client)
use_DynamoRIO_extension(coverage_client drmgr)
use_DynamoRIO_extension(coverage_client drx)
use_DynamoRIO_extension(coverage_client drreg)
use_DynamoRIO_extension(coverage_client drutil)
use_DynamoRIO_extension(coverage_client drwrap)
target_link_libraries(coverage_client Threads::Threads)