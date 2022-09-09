#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

void begin_session(session_t *sess)
{
	//开启套接字fd接收带外数据的功能
	activate_oobinline(sess->ctrl_fd); 
	/*
	int sockfds[2];
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");
	*/

	//这对套接字在当前进程就是它自己改变了，对父进程没影响，写时复制！！！！
	priv_sock_init(sess);  //sockpair搞出一对通信的套接字

	pid_t pid;
	pid = fork();   //创建孙子进程(服务进程)
	if (pid < 0)
		ERR_EXIT("fork");

	if (pid == 0)
	{
		// ftp服务进程
		/*
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		*/

		//因为你是父子进程模型。session是被继承的，但是我们的子进程是不需要sess->parent_fd的。
		//所以将它置为-1。
		//下面的设置父进程上下文也是同理。
		priv_sock_set_child_context(sess); //设置子进程上下文
		handle_child(sess);   //服务进程开始循环处理客户端命令啦！！！
	}
	else
	{

		// nobody进程
		
		/*
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		*/
		priv_sock_set_parent_context(sess); //设置父进程上下文

		handle_parent(sess);  //开始成为nobody进程默默守护孙子进程咯
	}
}