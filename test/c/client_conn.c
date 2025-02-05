// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <errno.h>
#include <time.h>
#define PORT 8080

int Send() {
    printf("xxxxxx1\n");

    char *hello = "Hello from client";
    struct iovec iov[1];
    iov[0].iov_base = hello;
    iov[0].iov_len = strlen(hello);

    struct msghdr mh;
    mh.msg_name = hello;
    mh.msg_namelen = strlen(hello);
    mh.msg_iov = iov;
    mh.msg_iovlen = 1;
    mh.msg_control = hello;;
    mh.msg_controllen = strlen(hello);
    mh.msg_flags = 0;

    printf("xxxxxx2\n");

    int sock = 0;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    printf("xxxxxx3\n");
    int ret = sendmsg(sock, &mh, 0);
    printf("output is %d\n", ret);
    return ret;
}

int main(int argc, char const *argv[]) 
{
    //printf("xxxxxx\n");
    //return Send();
    char *addr = "127.0.0.1";
    if (argc > 1)
    {
        addr = argv[1];
    }
    int port = PORT;
    if (argc > 2)
    {
        port = atoi(argv[2]);
    }
    printf("addr: %s, port: %d\n", addr, port);
    int sock = 0, valread;
    struct sockaddr_in serv_addr; 
    char *hello = "Hello from client"; 
    char buffer[1024] = {0}; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    }

    struct sockaddr_in sa;
    int sa_len;
    sa_len = sizeof(sa);
    printf("sa_len: %d\n", sa_len);
    printf("sock is %d\n", sock);
    printf("after calling socket()******************************\n");
    if (getsockname(sock, &sa, &sa_len) == -1) {
          perror("getsockname() failed");
          return -1;
    }
    printf("Local IP address is: %s\n", inet_ntoa(sa.sin_addr));
    printf("Local port is: %d\n", (int) ntohs(sa.sin_port));

    if (getpeername(sock, &sa, &sa_len) == -1) {
        printf("getpeername for server_fd, errorno: %d\n", errno);
            //   perror("getsockname() failed");
            //   return -1;
    }
    else {
        printf("Remote IP address is: %s\n", inet_ntoa(sa.sin_addr));
        printf("Remote port is: %d\n", (int) ntohs(sa.sin_port));
    }


    printf("start to connect \n");
    sleep(1);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    //if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
    if(inet_pton(AF_INET, addr, &serv_addr.sin_addr)<=0)
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 

    struct timespec tstart={0,0}, tend={0,0}; 
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double ns = (double)(tend.tv_sec - tstart.tv_sec) * 1.0e6 + (double)(tend.tv_nsec - tstart.tv_nsec)/1.0e3;
    printf("connection time used: %lf micro secs\n", ns);

    printf("Remote IP address is: %s\n", inet_ntoa(serv_addr.sin_addr));
    printf("Remote port is: %d\n", (int) ntohs(serv_addr.sin_port));

    // struct sockaddr_in sa;
    // int sa_len;
    // sa_len = sizeof(sa);
    printf("after calling connect()******************************\n");
    sleep(2);
    int sock1 = socket(AF_INET, SOCK_STREAM, 0);
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    connect(sock1, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    clock_gettime(CLOCK_MONOTONIC, &tend);
    ns = (double)(tend.tv_sec - tstart.tv_sec) * 1.0e6 + (double)(tend.tv_nsec - tstart.tv_nsec)/1.0e3;
    printf("connection time used: %lf micro secs\n", ns);
    sleep(2);
    int sock2 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock2, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock3 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock3, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock4 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock4, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock5 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock5, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock6 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock6, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock7 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock7, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock8 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock8, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock9 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock9, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock10 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock10, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock11 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock11, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock12 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock12, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock13 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock13, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock14 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock14, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock15 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock15, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock16 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock16, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock17 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock17, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock18 = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock18, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    sleep(2);
    int sock19 = socket(AF_INET, SOCK_STREAM, 0);
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    connect(sock19, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    clock_gettime(CLOCK_MONOTONIC, &tend);
    ns = (double)(tend.tv_sec - tstart.tv_sec) * 1.0e6 + (double)(tend.tv_nsec - tstart.tv_nsec)/1.0e3;
    printf("connection time used: %lf micro secs\n", ns);
    printf("all conenction is done\n");
    sleep(10);

    // if (getsockname(sock, &sa, &sa_len) == -1) {
    //       perror("getsockname() failed");
    //       return -1;
    // }
    // printf("Local IP address is: %s\n", inet_ntoa(sa.sin_addr));
    // printf("Local port is: %d\n", (int) ntohs(sa.sin_port));

    // if (getpeername(sock, &sa, &sa_len) == -1) {
    //     printf("getpeername for server_fd, errorno: %d\n", errno);
    //         //   perror("getsockname() failed");
    //         //   return -1;
    // }
    // else {
    //     printf("Remote IP address is: %s\n", inet_ntoa(sa.sin_addr));
    //     printf("Remote port is: %d\n", (int) ntohs(sa.sin_port));
    // }

    // valread = read(sock , buffer, 1024);
    // printf("%s\n",buffer );
    // int i = write(sock , hello , strlen(hello));
    // printf("client: Hello message sent %d bytes\n", i);

    // sleep(1);
    // i = send(sock , hello , strlen(hello) , 0 );
    // printf("client: Hello message sent %d bytes\n", i);
    // valread = recvfrom(sock , buffer, 1024, 0, &sa, &sa_len);
    // printf("%d recvfrom: %s\n", valread, buffer);
    // printf("recvfrom: Remote IP address is: %s\n", inet_ntoa(sa.sin_addr));
    // printf("recvfrom: Remote port is: %d\n", (int) ntohs(sa.sin_port));

    // struct iovec iov[3];
    // iov[0].iov_base = hello;
    // iov[0].iov_len = strlen(hello);
    // iov[1].iov_base = hello;
    // iov[1].iov_len = strlen(hello);
    // iov[2].iov_base = hello;
    // iov[2].iov_len = strlen(hello);

    // struct msghdr mh;
    // mh.msg_name = 0;
    // mh.msg_namelen = 0;
    // mh.msg_iov = iov;
    // mh.msg_iovlen = 3;
    // mh.msg_control = NULL;
    // mh.msg_controllen = 0;
    // mh.msg_flags = 0;

    // for (i=0; i< 10; i++) {
    //     int n = sendmsg(sock, &mh, 0);
    //     printf("client: sendmsg sent %d bytes\n", n);
    // }

    return 0;
} 
