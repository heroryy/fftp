#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "hash.h"

/*
typedef struct session
{
	// 控制连接
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// 父子进程通道
	int parent_fd;
	int child_fd;
} session_t;
*/

extern session_t *p_sess;
static unsigned int s_children;  //当前的子进程数量

static hash_t *s_ip_count_hash;  //ip和数量的hash表
static hash_t *s_pid_ip_hash;    //进程和ip的哈希表

void check_limits(session_t *sess);
void handle_sigchld(int sig);
unsigned int hash_func(unsigned int buckets, void *key);

unsigned int handle_ip_count(void *ip);
void drop_ip_count(void *ip);

int main(void)
{
	/*
	list_common();
	exit(EXIT_SUCCESS);
	*/

	// 字符串测试
	/*
	char *str1 = "		a b";
	char *str2 = "			  ";

	if (str_all_space(str1))
		printf("str1 all space\n");
	else
		printf("str1 not all space\n");

	if (str_all_space(str2))
		printf("str2 all space\n");
	else
		printf("str2 not all space\n");

	//char *str3 = "abcDef";		// 指针指向一个字符串常量，常量不能被修改
	char str3[] = "abcDef";
	str_upper(str3);
	printf("str3=%s\n", str3);

	long long result = str_to_longlong("12345678901234");
	printf("result = %lld\n", result);


	int n = str_octal_to_uint("711");
	printf("n=%d\n", n);
	*/

	

	parseconf_load_file(MINIFTP_CONF);
	//daemon(0, 0);

	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);

	printf("tunable_listen_port=%u\n", tunable_listen_port);
	printf("tunable_max_clients=%u\n", tunable_max_clients);
	printf("tunable_max_per_ip=%u\n", tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n", tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
	printf("tunable_local_umask=0%o\n", tunable_local_umask);
	printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);

	if (tunable_listen_address == NULL)
		printf("tunable_listen_address=NULL\n");
	else
		printf("tunable_listen_address=%s\n", tunable_listen_address);


	if (getuid() != 0)
	{
		fprintf(stderr, "miniftpd: must be started as root\n");
		exit(EXIT_FAILURE);
	}

/*
typedef struct session
{
	// 控制连接
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// 数据连接
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;

	// 限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;


	// 父子进程通道
	int parent_fd;
	int child_fd;

	// FTP协议状态
	int is_ascii;
	long long restart_pos;
	char *rnfr_name;
	int abor_received;

	// 连接数限制
	unsigned int num_clients;
	unsigned int num_this_ip;
} session_t;
*/

	session_t sess = 
	{
		/* 控制连接 */
		0, -1, "", "", "",
		/* 数据连接 */
		NULL, -1, -1, 0,
		/* 限速 */
		0, 0, 0, 0,
		/* 父子进程通道 */
		-1, -1,
		/* FTP协议状态 */
		0, 0, NULL, 0,
		/* 连接数限制 */
		0, 0
	};

	p_sess = &sess;

	sess.bw_upload_rate_max = tunable_upload_max_rate;  //用户是否指定，没有的话默认是0
	sess.bw_download_rate_max = tunable_download_max_rate;

	s_ip_count_hash = hash_alloc(256, hash_func);  //链地址法，256个桶
	s_pid_ip_hash = hash_alloc(256, hash_func);

	signal(SIGCHLD, handle_sigchld);  //在第12讲，我们是直接忽略了这个信号的
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	int conn;
	pid_t pid;
	struct sockaddr_in addr;

	while (1)
	{
		conn = accept_timeout(listenfd, &addr, 0);  //接受连接
		if (conn == -1)
			ERR_EXIT("accept_tinmeout");

		unsigned int ip = addr.sin_addr.s_addr; //取出这个32位整数
		
		//将当前ip的连接数保存在变量num_this_ip中，然后与配置项tunable_max_per_ip进行比较，
		//如果超过了就不让登录。当一个客户登录的时候，要在s_ip_count_hash更新这个表中的对应表项，
		//即该ip对应的连接数要加1，如果这个表项还不存在，要在表中添加一条记录，
		//并且将ip对应的连接数置1。

		++s_children;  //来了一条连接，子进程数量增加
		sess.num_clients = s_children;  //当前连接数(客户端数量)就等于子进程的数目
		sess.num_this_ip = handle_ip_count(&ip);  //保存当前ip的连接数
        //是否可以在这里直接进行检查？？？
		pid = fork();    //创建子进程
		if (pid == -1)
		{
			--s_children;  //不行就减
			//你可能会想，当前子进程创建失败了，那么sess.num_clients也应该减1.
			//事实上不必，因为下一条连接过来的时候，sess.num_clients = s_children;会被重新执行
			ERR_EXIT("fork");
		}

		if (pid == 0)   //子进程开启会话
		{
			close(listenfd);  //子进程关闭监听套接字
			sess.ctrl_fd = conn;   //并且记录通信的套接字

			
			//为啥是在子进程检查呢(可能子进程是会话的开启者，它检查通过了，会话才能顺利开启)
			//检查不通过的话，子进程就自己退出了。
			//你现在有一个连接进来了，我肯定要先接受这个连接提取出ip，才知道这个ip的连接数
			//是否超出限制了呀

			//这里都是检查不通过，子进程自己再退出，是否可以先检查，通过了再创建子进程？
			check_limits(&sess);   

			//这里其实是儿子进程(当前进程)退出，可能是检查不通过，然后会触发父进程的信号处理程序。
			//但是信号是会被继承的，当孙子进程(服务进程)退出的时候，儿子进程(当前进程)是没有必要
			//执行handle_sigchld函数的，这是当前进程退出的时候的它的爹要处理的事。
			//尽管执行这个信号处理函数，不会带来实质的影响。因为那些变量是写时共享的嘛
			signal(SIGCHLD, SIG_IGN);  //所以忽略孙子进程退出，同时也可以避免僵尸进程



			begin_session(&sess);  //开启会话咯
		}
		else  //父进程关闭连接套接字
		{
			//维护oid和ip的映射关系。
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid),
				&ip, sizeof(unsigned int));
			
			close(conn);
		}
	}
	return 0;
}


//这里都是检查不通过，子进程自己再退出，是否可以先检查，通过了再创建子进程？
void check_limits(session_t *sess)
{
	//先是最大连接数不要超过限制
	if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, 
			"There are too many connected users, please try later.");

		exit(EXIT_FAILURE);
	}
	//再是每个ip的链接数不要超过限制
	if (tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, 
			"There are too many connections from your internet address.");

		exit(EXIT_FAILURE);
	}
	//这里超过了限制，子进程退出的时候，需要将哈希表中该ip的连接数减去1
	//怎么实现呢？因为子进程退出的时候，会发送信号给父进程，父进程能够知道是哪个pid退出了
	//但是它仍旧不知道是哪个ip退出了，所以我们需要建立pid和ip的哈希表。

	//我们不能直接在这里退出时将哈希表中该ip的连接数减去1。这里操作的是子进程的哈希表，
	//不是父进程的。牢记进程模型呀。
}


void handle_sigchld(int sig)
{
	// 当一个客户端退出的时候，那么该客户端对应ip的连接数要减1，
	// 处理过程是这样的，首先是客户端退出的时候，
	// 父进程需要知道这个客户端的ip，这可以通过在s_pid_ip_hash查找得到，
	

	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)  //循环等待子进程退出
	{
		--s_children;  //子进程个数减1
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL)
		{
			continue;
		}

		drop_ip_count(ip);  
		//这个进程已经退出了，那么该pid的映射也没有存在的价值了
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}

}

unsigned int hash_func(unsigned int buckets, void *key)
{
	unsigned int *number = (unsigned int*)key;

	return (*number) % buckets;
}

unsigned int handle_ip_count(void *ip)  //返回当前ip的链接数
{
	// 当一个客户登录的时候，要在s_ip_count_hash更新这个表中的对应表项,
	// 即该ip对应的连接数要加1，如果这个表项还不存在，要在表中添加一条记录，
	// 并且将ip对应的连接数置1。

	unsigned int count;
	//注意返回的是地址呀
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash,
		ip, sizeof(unsigned int));
	if (p_count == NULL)
	{
		count = 1;
		hash_add_entry(s_ip_count_hash, ip, sizeof(unsigned int),
			&count, sizeof(unsigned int));
	}
	else
	{
		count = *p_count;
		++count;
		*p_count = count;  //写回到原地址
	}

	return count;
}


void drop_ip_count(void *ip)
{
	// 得到了ip进而我们就可以在s_ip_count_hash表中找到对应的连接数，进而进行减1操作。

	unsigned int count;
	//返回的是地址呀，你当然是在对哈希表进行操作
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash,
		ip, sizeof(unsigned int));
	if (p_count == NULL)  //基本不可能的
	{
		return;
	}

	if (count <= 0)   //基本不可能的
	{
		return;
	}
	count = *p_count;
	--count;
	*p_count = count;

	if (count == 0)  //这个表项已经没有存在的价值了
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}
