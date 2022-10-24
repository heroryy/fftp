#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"


void ftp_lreply(session_t *sess, int status, const char *text);

void handle_alarm_timeout(int sig); //处理闹钟
void handle_sigalrm(int sig);  //处理重新安装的闹钟信号(主要是数据连接空闲带来了影响)
void handle_sigurg(int sig);   //处理SIGRUG信号，此时意味着接收了外带数据，即可能是收到了ABORcmd
void start_cmdio_alarm(void);  //开始闹钟。控制连接闹钟。
void start_data_alarm(void);   //重新安装闹钟信号，之前的自动失效。数据连接闹钟

void check_abor(session_t *sess);

int list_common(session_t *sess, int detail);
void limit_rate(session_t *sess, int bytes_transfered, int is_upload);
void upload_common(session_t *sess, int is_append); //是否是appe的方式

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);
int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);  //仅仅是为了防止空闲断开
static void do_help(session_t *sess);


static void do_site_chmod(session_t *sess, char *chmod_arg);
static void do_site_umask(session_t *sess, char *umask_arg);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	/*do_stru*/NULL	},
	{"MODE",	/*do_mode*/NULL	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};

session_t *p_sess; //因为我们没有给下面这个函数传递session，
                   //但是我们下面这个函数又需要session

void handle_alarm_timeout(int sig)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD); //(系统函数)先关闭读的这一半，即不再接收客户端的消息
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout."); //给客户端发回响应
	shutdown(p_sess->ctrl_fd, SHUT_WR); //再关闭读的这一半，不再给客户端发送消息了
	exit(EXIT_FAILURE); //孙子进程退出,将会导致儿子进程也退出
}

void handle_sigalrm(int sig)
{
	if (!p_sess->data_process) //数据连接开始，但是没有在传输数据的状态
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}

	// 否则，当前处于数据传输的状态收到了超时信号
	p_sess->data_process = 1;  //标记它是在传输数据
	start_data_alarm(); //那么重新启动数据连接闹钟
}

void handle_sigurg(int sig)
{
	if (p_sess->data_fd == -1)  //没有处于数据传输的状态，无需再处理
	{
		return;
	}

	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);
	if (ret <= 0)
	{
		ERR_EXIT("readline");
	}
	str_trim_crlf(cmdline); //ABOR命令(没有参数)可能收到这两种形式的字符串
	if (strcmp(cmdline, "ABOR") == 0
		|| strcmp(cmdline, "\377\364\377\362ABOR") == 0)
	{
		p_sess->abor_received = 1; //标记收到了ABOR命令
		shutdown(p_sess->data_fd, SHUT_RDWR); //读写的都断开,不能再传输数据了
	}
	else  //非法的命令
	{
		ftp_reply(p_sess, FTP_BADCMD, "Unknown command.");
	}
}

void check_abor(session_t *sess)
{
	if (sess->abor_received) //有接收到ABOR命令
	{
		sess->abor_received = 0; //置为0
		ftp_reply(p_sess, FTP_ABOROK, "ABOR successful.");//处理完毕226应答
	}
}

void start_cmdio_alarm(void)  
{
	if (tunable_idle_session_timeout > 0)
	{
		// 安装信号
		signal(SIGALRM, handle_alarm_timeout);
		// 启动闹钟(经过timeout这么长的时间以后将会发送SIGALRM信号给当前进程)
		alarm(tunable_idle_session_timeout);
	}
}

void start_data_alarm(void)
{
	if (tunable_data_connection_timeout > 0) //你要配置了这个选项
		//                                     处理数据连接不传输数据的特殊case
	{
		// 安装信号
		signal(SIGALRM, handle_sigalrm); //数据传输的闹钟信号
		// 启动闹钟
		alarm(tunable_data_connection_timeout);
	}
	else if (tunable_idle_session_timeout > 0)
	{
		// 关闭先前安装的闹钟
		alarm(0); //主要是为了我在数据传输的时候，为控制连接而设立的闹钟不要影响到我！
		//等我数据连接传输完毕了，我会再开启你这个控制连接的闹钟的。
	}
}

void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");
	int ret;

	//循环处理收到的客户端命令
	while (1)
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline)); //命令行
		memset(sess->cmd, 0, sizeof(sess->cmd)); //命令
		memset(sess->arg, 0, sizeof(sess->arg)); //参数

		start_cmdio_alarm();  //安装闹钟咯(处理空闲断开)
						      //每接收一次命令，就刷新一次闹钟
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if (ret == -1)
			ERR_EXIT("readline");
		else if (ret == 0)
			exit(EXIT_SUCCESS);

		printf("cmdline=[%s]\n", sess->cmdline);
		// 去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n", sess->cmdline);
		// 解析FTP命令与参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		// 将命令转换为大写
		str_upper(sess->cmd);
		// 处理FTP命令
		/*
		if (strcmp("USER", sess->cmd) == 0)
		{
			do_user(sess);
		}
		else if (strcmp("PASS", sess->cmd) == 0)
		{
			do_pass(sess);
		}
		*/

		int i;
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);

		//从所有注册的命令中寻找对于的处理函数，命令参数被保存在session中。
		//如果有命令，无动作(即注册的处理函数是NULL)，那么响应命令未实现处理动作
		for (i=0; i<size; i++)
		{
			if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if (ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);
				}
				else
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				
				break;
			}
		}

		//找不到，不认识这条命令。
		if (i == size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));  //使用通信的fd发回响应。
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

int list_common(session_t *sess, int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL)
	{
		if (lstat(dt->d_name, &sbuf) < 0) //lstat，如果是软链接，返回链接文件本身的信息
		{
			continue; //一个文件失败了，不要直接结束，继续即可
		}
		if (dt->d_name[0] == '.') //不显示隐藏文件
			continue;

		char buf[1024] = {0};
		if (detail)  //是否详细显示
		{
			const char *perms = statbuf_get_perms(&sbuf);

			
			int off = 0;
			off += sprintf(buf, "%s ", perms);
			off += sprintf(buf + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

			const char *datebuf = statbuf_get_date(&sbuf);
			off += sprintf(buf + off, "%s ", datebuf);
			if (S_ISLNK(sbuf.st_mode))
			{
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}
		
		//printf("%s", buf);
		writen(sess->data_fd, buf, strlen(buf));
	}

	closedir(dir);

	return 1;
}

void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	sess->data_process = 1;  //在这里标记数据正在传输中是不太妥当的

	// 睡眠时间 = (当前传输速度 / 最大传输速度 – 1) * 当前传输时间;
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)1000000;
	if (elapsed <= (double)0)
	{
		elapsed = (double)0.01;
	}


	// 计算当前传输速度
	unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);

	double rate_ratio;
	if (is_upload)
	{
		if (bw_rate <= sess->bw_upload_rate_max)
		{
			// 不需要限速
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	else
	{
		if (bw_rate <= sess->bw_download_rate_max)
		{
			// 不需要限速
			sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = curr_usec;
			return;
		}

		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	// 睡眠时间 = (当前传输速度 / 最大传输速度 – 1) * 当前传输时间;
	double pause_time;
	pause_time = (rate_ratio - (double)1) * elapsed;

	nano_sleep(pause_time);

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

}

void upload_common(session_t *sess, int is_append)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}

	long long offset = sess->restart_pos;  //断点的话先从REST命令拿到断点位置
	sess->restart_pos = 0;  //重新置0

	// 打开且创建文件(这个有可能给的是设备文件名,所以后面是需要做判断的)
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666); //创建且只写的方式打开文件
	if (fd == -1)
	{   //失败响应
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	int ret;
	// 加写锁
	ret = lock_file_write(fd);
	if (ret == -1)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// STOR
	// REST+STOR
	// APPE
	if (!is_append && offset == 0)		// STOR
	{
		//这种模式下，文件可能是存在的，我们将它清零一下
		ftruncate(fd, 0);
		if (lseek(fd, 0, SEEK_SET) < 0) //然后文件偏移到文件头的位置
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (!is_append && offset != 0)		// REST+STOR
	{
		if (lseek(fd, offset, SEEK_SET) < 0) //续传偏移到断点位置
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (is_append)				// APPE
	{
		//事实上，这种模式下，客户端自己也要维护一个文件尾的偏移量
		//我们服务器只需要偏移到末尾即可。
		if (lseek(fd, 0, SEEK_END) < 0) //追加偏移到文件的末尾
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))   //有必要的
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// 150
	char text[1024] = {0};
	if (sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}

	ftp_reply(sess, FTP_DATACONN, text);

	int flag = 0;
	// 上传文件

	char buf[1024];

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	while (1)  //循环读完对方发送过来的数据
	{
		ret = read(sess->data_fd, buf, sizeof(buf));
		if (ret == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				flag = 2;
				break;
			}
		}
		else if (ret == 0) //对方关闭了连接
		{
			flag = 0;
			break;
		}

		limit_rate(sess, ret, 1);
		if (sess->abor_received)
		{
			flag = 2;
			break;
		}

		if (writen(fd, buf, ret) != ret)  //写入到文件中
		{
			flag = 1;
			break;
		}
	}


	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;

	close(fd);

	if (flag == 0 && !sess->abor_received)
	{
		// 226 //成功的应答
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if (flag == 1)
	{
		// 451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writting to local file.");
	}
	else if (flag == 2)
	{
		// 426
		ftp_reply(sess, FTP_BADSENDNET, "Failure reading from network stream.");
	}

	check_abor(sess);
	// 重新开启控制连接通道闹钟
	start_cmdio_alarm();
}


int port_active(session_t *sess)
{
	if (sess->port_addr)
	{
		if (pasv_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

int pasv_active(session_t *sess)
{
	/*
	if (sess->pasv_listen_fd != -1)
	{
		if (port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	*/
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);
	if (active)
	{
		if (port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int get_port_fd(session_t *sess)   //得到主动模式下的数据传输套接字
{
	/*
	向nobody发送PRIV_SOCK_GET_DATA_SOCK命令        1
	向nobody发送一个整数port		       4
	向nobody发送一个字符串ip                       不定长
	*/

	printf("ifiififififiiiiiiiiiii\n");
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK); //先发送命令，再发送数据
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	char res = priv_sock_get_result(sess->child_fd);  //读取响应结果
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		printf("response failed\n");
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK)  //响应成功
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd); //接收这条数据传输的通信的套接字
	}

	return 1;
}

int get_pasv_fd(session_t *sess) //得到被动模式数据传输套接字
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}

	return 1;
}

int get_transfer_fd(session_t *sess) //得到数据传输套接字(主动或者被动)
{
	// 检测是否收到PORT或者PASV命令
	if (!port_active(sess) && !pasv_active(sess))
	{
		//printf("yyyyyyyyyyyyyyyy\n");
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}

	int ret = 1;
	// 如果是主动模式
	if (port_active(sess))
	{

		/*
		socket
		bind 20
		connect
		*/
		// tcp_client(20);

		/*
		int fd = tcp_client(0);
		if (connect_timeout(fd, sess->port_addr, tunable_connect_timeout) < 0)
		{
			close(fd);
			return 0;
		}

		sess->data_fd = fd;
		*/
		printf("port port port\n");
		if (get_port_fd(sess) == 0)  //得到数据连接的通信的套接字
		{
			printf("000000000000000\n");
			ret = 0;
		}
	}

	if (pasv_active(sess))
	{
		/*
		int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
		close(sess->pasv_listen_fd);

		if (fd == -1)
		{
			return 0;
		}

		sess->data_fd = fd;
		*/
		if (get_pasv_fd(sess) == 0)
		{
			ret = 0;
		}

	}

	
	if (sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}

	if (ret)
	{
		// 重新安装SIGALRM信号(为了数据连接)，并启动闹钟
		// 当数据套接字创建好以后，我们认为数据连接启动。
		start_data_alarm();
	}

	return ret;
}

static void do_user(session_t *sess)
{
	//USER jjl
	struct passwd *pw = getpwnam(sess->arg);  //先用用户名获取信息
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	sess->uid = pw->pw_uid;  //记录pid，用于后续密码验证功能的实现
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
	
}

static void do_pass(session_t *sess)
{
	// PASS 123456
	// leapFtp是明文传输密码的
	struct passwd *pw = getpwuid(sess->uid);  
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	printf("name=[%s]\n", pw->pw_name);

	struct spwd *sp = getspnam(pw->pw_name); 
	if (sp == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	// 将明文进行加密
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	// 验证密码
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	signal(SIGURG, handle_sigurg);  //为SIGURG注册处理函数
	activate_sigurg(sess->ctrl_fd); //开启该fd能够接收sigurg信号

	umask(tunable_local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_cwd(session_t *sess)
{
	if (chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess)
{
	if (chdir("..") < 0)  //改变目录就行
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}

	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
	exit(EXIT_SUCCESS);  //孙子进程退出,将会导致儿子进程跟着退出
}

static void do_port(session_t *sess)
{
	//PORT 192,168,0,100,123,233
	unsigned int v[6];

	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char *)&sess->port_addr->sin_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
	//Entering Passive Mode (192,168,244,100,101,46).

	char ip[16] = {0};
	getlocalip(ip);

/*
	sess->pasv_listen_fd = tcp_server(ip, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}

	unsigned short port = ntohs(addr.sin_port);
	*/

	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = (int)priv_sock_get_int(sess->child_fd);


	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", 
		v[0], v[1], v[2], v[3], port>>8, port&0xFF);

	ftp_reply(sess, FTP_PASVOK, text);


}

static void do_type(session_t *sess)  //传输类型
{
	if (strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}

}
/*
static void do_stru(session_t *sess)
{
}

static void do_mode(session_t *sess)
{
}
*/

static void do_retr(session_t *sess)
{
	// 下载文件
	// 断点续载

	// 创建数据连接(可能是主动或被动模式)
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	//下载中的文件，按下暂停后，客户端会主动断开这条连接，为当前
	//用户开辟的两个进程也会消失，然后，下一次客户端再连接过来的
	//时候，会先发送`REST offset`命令，然后再发送RETR命令继续进行下载。
	//客户端只是断开了连接，客户端进程(如leapftp)又没有结束，它当然能够保存
	//断点位置咯。与你的多进程模型没有关系，客户端断开，孙子和儿子进程都会消失。
	long long offset = sess->restart_pos; //获取偏移量(断点位置)
	sess->restart_pos = 0;

	// 打开文件
	int fd = open(sess->arg, O_RDONLY); //每次都打开文件
	if (fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	int ret;
	// 加读锁
	ret = lock_file_read(fd); //这里重点看看
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	// 判断是否是普通文件(if is device file,dont send)
	struct stat sbuf;
	ret = fstat(fd, &sbuf); //通过fd而不是文件名获取属性。(就是文件名或fd都可以获取属性啦)
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	if (offset != 0)
	{
		ret = lseek(fd, offset, SEEK_SET); //尝试移动到上一次的位置
		if (ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
			return;
		}
	}

//150 Opening BINARY mode data connection for /home/jjl/tmp/echocli.c (1085 bytes).

	// 150
	// 这两种传输模式的区别在于是否对"\r\n"进行转化，二进制传输不进行转换。
	// 推荐使用二进制方式进行传输。因为ascii模式，是文本文件的话，没有影响。
	// 是二进制文件的话，可能会导致传输后的文件无法使用。
	// 具体的传输方式不是一个type命令就能决定的，配置文件中还有
	//   # ASCII mangling is a horrible feature of the protocol.
    //   #ascii_upload_enable=YES
    //   #ascii_download_enable=YES
    //这两个选项来决定，由于我们默认使用二进制模式传输，且不在配置文件中
	//生成这两个选项，所以type命令其实是没有作用的，但是你需要给客户端发回响应，
	//否则客户端会阻塞。
	char text[1024] = {0};
	if (sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).",
			sess->arg, (long long)sbuf.st_size);
	}

	ftp_reply(sess, FTP_DATACONN, text);

	int flag = 0;
	// 下载文件

	/*char buf[4096];  //whether can be more bigger? 

	while (1)
	{
		ret = read(fd, buf, sizeof(buf));
		if (ret == -1)
		{
			if (errno == EINTR)  //这个还需要处理信号中断
			{
				continue;
			}
			else
			{
				flag = 1;  //fail
				break;
			}
		}
		else if (ret == 0)
		{
			flag = 0;  //succ
			break;
		}

		if (writen(sess->data_fd, buf, ret) != ret)
		{
			flag = 2;  //fail
			break;
		}
	}
	*/

	// ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

	long long bytes_to_send = sbuf.st_size;
	if (offset > bytes_to_send) //断点位置比整个文件大小还要大
	{
		bytes_to_send = 0; //那么没有数据可以发送
	}
	else
	{
		bytes_to_send -= offset;
	}

	//记录传输开始的时间
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	while (bytes_to_send)
	{
		//不足4096，发送实际还剩下的字节数
		//是否可以更大以加快速度
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		//调用sendfile，一次发送4096字节

		//NULL 代表自动更新偏移位置
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
		if (ret == -1)
		{
			flag = 2;  //其实不知道是读文件失败，还是写入到数据套接字失败了
			break;     //做成2就行
		}

		limit_rate(sess, ret, 0);
		if (sess->abor_received)
		{
			flag = 2;
			break;
		}

		bytes_to_send -= ret;
	}

	if (bytes_to_send == 0)
	{
		flag = 0;  //succ
	}

	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;

	close(fd);  //close file

	

	if (flag == 0 && !sess->abor_received) //如果是刚好传输完了接收到了abor命令
	{                                      //我们推迟一下响应。在check_abor中做响应。
		// 226
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else if (flag == 1)
	{
		// 451
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");
	}
	else if (flag == 2)
	{
		// 426
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");
	}

	check_abor(sess);  //刚好数据传输做完了，但是有abor命令过来
	                   //我们也应该检测一下。检测的是控制连接fd，
					   //放这里是没问题的，上面关闭的是数据连接fd。
	// 重新开启控制连接通道闹钟(别忘啦)
	start_cmdio_alarm();
	
}

static void do_stor(session_t *sess)
{
	upload_common(sess, 0);
}

static void do_appe(session_t *sess)
{
	upload_common(sess, 1);
}

static void do_list(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	// 150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	list_common(sess, 1);
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");


}

static void do_nlst(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	// 150
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	list_common(sess, 0);
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

static void do_rest(session_t *sess)  //先发送REST命令，服务端记录断点位置。再上传或下载！！！
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}

static void do_abor(session_t *sess) //此时没有数据在传输，走到不是紧急通道
{                                    //直接响应一个没有在进行数据传输即可
	ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR");
	
}

static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024+1] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);

	ftp_reply(sess, FTP_PWDOK, text);
}

static void do_mkd(session_t *sess)
{
	// 0777 & umask
	if (mkdir(sess->arg, 0777) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return;
	}
	
	char text[4096] = {0};
	if (sess->arg[0] == '/')
	{
		sprintf(text, "%s created", sess->arg);
	}
	else
	{
		char dir[4096+1] = {0};
		getcwd(dir, 4096);
		if (dir[strlen(dir)-1] == '/')
		{
			sprintf(text, "%s%s created", dir, sess->arg);
		}
		else
		{
			sprintf(text, "%s/%s created", dir, sess->arg);
		}
	}

	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_rmd(session_t *sess)
{
	if (rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
	}

	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");

}

static void do_dele(session_t *sess)
{
	if (unlink(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return;
	}

	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg) + 1);
	memset(sess->rnfr_name, 0, strlen(sess->arg) + 1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
	if (sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}

	rename(sess->rnfr_name, sess->arg);

	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}


static void do_site(session_t *sess)
{
	// SITE CHMOD <perm> <file>
	// SITE UMASK [umask]
	// SITE HELP

	char cmd[100] = {0};
	char arg[100] = {0};

	str_split(sess->arg , cmd, arg, ' ');
	if (strcmp(cmd, "CHMOD") == 0)
	{
		do_site_chmod(sess, arg);
	}
	else if (strcmp(cmd, "UMASK") == 0)
	{
		do_site_umask(sess, arg);
	}
	else if (strcmp(cmd, "HELP") == 0)
	{
		ftp_reply(sess, FTP_SITEHELP, "CHMOD UMASK HELP");
	}
	else
	{
		 ftp_reply(sess, FTP_BADCMD, "Unknown SITE command.");
	}

}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}

static void do_size(session_t *sess)
{
	//550 Could not get file size.

	struct stat buf;
	if (stat(sess->arg, &buf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}

	if (!S_ISREG(buf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}

	char text[1024] = {0};
	sprintf(text, "%lld", (long long)buf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

static void do_stat(session_t *sess)
{
	ftp_lreply(sess, FTP_STATOK, "FTP server status:");
	if (sess->bw_upload_rate_max == 0)
	{
		char text[1024];
		sprintf(text,
			"     No session upload bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if (sess->bw_upload_rate_max > 0)
	{
		char text[1024];
		sprintf(text,
			"     Session upload bandwidth limit in byte/s is %u\r\n",
			sess->bw_upload_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}

	if (sess->bw_download_rate_max == 0)
	{
		char text[1024];
		sprintf(text,
			"     No session download bandwidth limit\r\n");
		writen(sess->ctrl_fd, text, strlen(text));
	}
	else if (sess->bw_download_rate_max > 0)
	{
		char text[1024];
		sprintf(text,
			"     Session download bandwidth limit in byte/s is %u\r\n",
			sess->bw_download_rate_max);
		writen(sess->ctrl_fd, text, strlen(text));
	}

	char text[1024] = {0};
	sprintf(text,
		"     At session startup, client count was %u\r\n",
		sess->num_clients);
	writen(sess->ctrl_fd, text, strlen(text));
	
	ftp_reply(sess, FTP_STATOK, "End of status");
}

static void do_noop(session_t *sess)
{
	ftp_reply(sess, FTP_NOOPOK, "NOOP ok.");

}

static void do_help(session_t *sess)
{
	ftp_lreply(sess, FTP_HELP, "The following commands are recognized.");
	writen(sess->ctrl_fd,
		" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n",
		strlen(" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"));
	writen(sess->ctrl_fd,
		" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n",
		strlen(" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"));
	writen(sess->ctrl_fd,
		" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n",
		strlen(" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
	writen(sess->ctrl_fd,
		" XPWD XRMD\r\n",
		strlen(" XPWD XRMD\r\n"));
	ftp_reply(sess, FTP_HELP, "Help OK.");
}

static void do_site_chmod(session_t *sess, char *chmod_arg)
{
	// SITE CHMOD <perm> <file>
	if (strlen(chmod_arg) == 0)
	{
		ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	char perm[100] = {0};
	char file[100] = {0};
	str_split(chmod_arg , perm, file, ' ');
	if (strlen(file) == 0)
	{
		ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
		return;
	}

	unsigned int mode = str_octal_to_uint(perm);
	if (chmod(file, mode) < 0)
	{
		ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command failed.");
	}
	else
	{
		ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command ok.");
	}
}

static void do_site_umask(session_t *sess, char *umask_arg)
{
	// SITE UMASK [umask]
	if (strlen(umask_arg) == 0)
	{
		char text[1024] = {0};
		sprintf(text, "Your current UMASK is 0%o", tunable_local_umask);
		ftp_reply(sess, FTP_UMASKOK, text);
	}
	else
	{
		unsigned int um = str_octal_to_uint(umask_arg);
		umask(um);
		char text[1024] = {0};
		sprintf(text, "UMASK set to 0%o", um);
		ftp_reply(sess, FTP_UMASKOK, text);
	}
}
