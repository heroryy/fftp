/*************************************************************************
	> File Name: k.c
	> Author: hero
	> Mail: @hero 
	> Created Time: 2022年09月06日 星期二 20时30分37秒
 ************************************************************************/

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define ERR_EXIT(m) \
        do \
	{ \
           	perror(m); \
                exit(EXIT_FAILURE); \
        } while(0)

int main(void)
{
        int listenfd;  //手机
    	//前面两个字段已经可以确定协议类型，所以第三个参数填0，让其自动显示。当然也可以显示指定。
        if ((listenfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
/*	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)*/
                ERR_EXIT("socket");  

        struct sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(20);  //转成网络字节序的端口哦
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY); //将任意的ip地址转换为网络字节序的整数
    	
    	//将点分10进制的ip地址转换为网络字节序的整数，结果是网络字节序！！！！
        /*servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");*/
        /*inet_aton("127.0.0.1", &servaddr.sin_addr);*/
		
    	int on = 1;   //设置端口复用
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
                ERR_EXIT("setsockopt");

    
    	//绑定电话号码        //转成通用地址结构             //并给出大小
        if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
                ERR_EXIT("bind");
    	//等待别人打电话来
        if (listen(listenfd, SOMAXCONN) < 0) //队列最大值，已完成连接队列和未完成连接队列的总和
                ERR_EXIT("listen");

        struct sockaddr_in peeraddr;
        socklen_t peerlen = sizeof(peeraddr);
        int conn;
    	//接电话      //等待连接，就像打电话一样，我们当然可以知道对等方的地址
        if ((conn = accept(listenfd, (struct sockaddr*)&peeraddr, &peerlen)) < 0)
                ERR_EXIT("accept");

        char recvbuf[1024];
        while (1)
        {
                memset(recvbuf, 0, sizeof(recvbuf));
            	//read返回真实读取到的字节数
                int ret = read(conn, recvbuf, sizeof(recvbuf));
            	//我想，对于fputs这种函数，它当然是针对文件操作的。
            	//字面意思就是，将内容输出到一个文件里，那么很显然，标准输出也是一个
            	//文件，我们完全可以输出到标准输出。
                fputs(recvbuf, stdout);
                write(conn, recvbuf, ret); //收到多少字节，就发回去多少字节
                //也可以使用strlen(recvbuf)进行发送，但是不建议使用sizeof(recvbuf)进行发送，因为
            	//这样会发送更多的字节数，虽然都是'\0'不会对结果造成影响。
        }
		close(conn);
        close(listenfd);

        return 0;
}
