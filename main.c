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
	// ��������
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// ���ӽ���ͨ��
	int parent_fd;
	int child_fd;
} session_t;
*/

extern session_t *p_sess;
static unsigned int s_children;  //��ǰ���ӽ�������

static hash_t *s_ip_count_hash;  //ip��������hash��
static hash_t *s_pid_ip_hash;    //���̺�ip�Ĺ�ϣ��

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

	// �ַ�������
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

	//char *str3 = "abcDef";		// ָ��ָ��һ���ַ����������������ܱ��޸�
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
	// ��������
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// ��������
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;

	// ����
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;


	// ���ӽ���ͨ��
	int parent_fd;
	int child_fd;

	// FTPЭ��״̬
	int is_ascii;
	long long restart_pos;
	char *rnfr_name;
	int abor_received;

	// ����������
	unsigned int num_clients;
	unsigned int num_this_ip;
} session_t;
*/

	session_t sess = 
	{
		/* �������� */
		0, -1, "", "", "",
		/* �������� */
		NULL, -1, -1, 0,
		/* ���� */
		0, 0, 0, 0,
		/* ���ӽ���ͨ�� */
		-1, -1,
		/* FTPЭ��״̬ */
		0, 0, NULL, 0,
		/* ���������� */
		0, 0
	};

	p_sess = &sess;

	sess.bw_upload_rate_max = tunable_upload_max_rate;  //�û��Ƿ�ָ����û�еĻ�Ĭ����0
	sess.bw_download_rate_max = tunable_download_max_rate;

	s_ip_count_hash = hash_alloc(256, hash_func);  //����ַ����256��Ͱ
	s_pid_ip_hash = hash_alloc(256, hash_func);

	signal(SIGCHLD, handle_sigchld);  //�ڵ�12����������ֱ�Ӻ���������źŵ�
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	int conn;
	pid_t pid;
	struct sockaddr_in addr;

	while (1)
	{
		conn = accept_timeout(listenfd, &addr, 0);  //��������
		if (conn == -1)
			ERR_EXIT("accept_tinmeout");

		unsigned int ip = addr.sin_addr.s_addr; //ȡ�����32λ����
		
		//����ǰip�������������ڱ���num_this_ip�У�Ȼ����������tunable_max_per_ip���бȽϣ�
		//��������˾Ͳ��õ�¼����һ���ͻ���¼��ʱ��Ҫ��s_ip_count_hash����������еĶ�Ӧ���
		//����ip��Ӧ��������Ҫ��1����������������ڣ�Ҫ�ڱ������һ����¼��
		//���ҽ�ip��Ӧ����������1��

		++s_children;  //����һ�����ӣ��ӽ�����������
		sess.num_clients = s_children;  //��ǰ������(�ͻ�������)�͵����ӽ��̵���Ŀ
		sess.num_this_ip = handle_ip_count(&ip);  //���浱ǰip��������
        //�Ƿ����������ֱ�ӽ��м�飿����
		pid = fork();    //�����ӽ���
		if (pid == -1)
		{
			--s_children;  //���оͼ�
			//����ܻ��룬��ǰ�ӽ��̴���ʧ���ˣ���ôsess.num_clientsҲӦ�ü�1.
			//��ʵ�ϲ��أ���Ϊ��һ�����ӹ�����ʱ��sess.num_clients = s_children;�ᱻ����ִ��
			ERR_EXIT("fork");
		}

		if (pid == 0)   //�ӽ��̿����Ự
		{
			close(listenfd);  //�ӽ��̹رռ����׽���
			sess.ctrl_fd = conn;   //���Ҽ�¼ͨ�ŵ��׽���

			
			//Ϊɶ�����ӽ��̼����(�����ӽ����ǻỰ�Ŀ����ߣ������ͨ���ˣ��Ự����˳������)
			//��鲻ͨ���Ļ����ӽ��̾��Լ��˳��ˡ�
			//��������һ�����ӽ����ˣ��ҿ϶�Ҫ�Ƚ������������ȡ��ip����֪�����ip��������
			//�Ƿ񳬳�������ѽ

			//���ﶼ�Ǽ�鲻ͨ�����ӽ����Լ����˳����Ƿ�����ȼ�飬ͨ�����ٴ����ӽ��̣�
			check_limits(&sess);   

			//������ʵ�Ƕ��ӽ���(��ǰ����)�˳��������Ǽ�鲻ͨ����Ȼ��ᴥ�������̵��źŴ������
			//�����ź��ǻᱻ�̳еģ������ӽ���(�������)�˳���ʱ�򣬶��ӽ���(��ǰ����)��û�б�Ҫ
			//ִ��handle_sigchld�����ģ����ǵ�ǰ�����˳���ʱ������ĵ�Ҫ������¡�
			//����ִ������źŴ��������������ʵ�ʵ�Ӱ�졣��Ϊ��Щ������дʱ�������
			signal(SIGCHLD, SIG_IGN);  //���Ժ������ӽ����˳���ͬʱҲ���Ա��⽩ʬ����



			begin_session(&sess);  //�����Ự��
		}
		else  //�����̹ر������׽���
		{
			//ά��oid��ip��ӳ���ϵ��
			hash_add_entry(s_pid_ip_hash, &pid, sizeof(pid),
				&ip, sizeof(unsigned int));
			
			close(conn);
		}
	}
	return 0;
}


//���ﶼ�Ǽ�鲻ͨ�����ӽ����Լ����˳����Ƿ�����ȼ�飬ͨ�����ٴ����ӽ��̣�
void check_limits(session_t *sess)
{
	//���������������Ҫ��������
	if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients)
	{
		ftp_reply(sess, FTP_TOO_MANY_USERS, 
			"There are too many connected users, please try later.");

		exit(EXIT_FAILURE);
	}
	//����ÿ��ip����������Ҫ��������
	if (tunable_max_per_ip > 0 && sess->num_this_ip > tunable_max_per_ip)
	{
		ftp_reply(sess, FTP_IP_LIMIT, 
			"There are too many connections from your internet address.");

		exit(EXIT_FAILURE);
	}
	//���ﳬ�������ƣ��ӽ����˳���ʱ����Ҫ����ϣ���и�ip����������ȥ1
	//��ôʵ���أ���Ϊ�ӽ����˳���ʱ�򣬻ᷢ���źŸ������̣��������ܹ�֪�����ĸ�pid�˳���
	//�������Ծɲ�֪�����ĸ�ip�˳��ˣ�����������Ҫ����pid��ip�Ĺ�ϣ��

	//���ǲ���ֱ���������˳�ʱ����ϣ���и�ip����������ȥ1��������������ӽ��̵Ĺ�ϣ��
	//���Ǹ����̵ġ��μǽ���ģ��ѽ��
}


void handle_sigchld(int sig)
{
	// ��һ���ͻ����˳���ʱ����ô�ÿͻ��˶�Ӧip��������Ҫ��1��
	// ��������������ģ������ǿͻ����˳���ʱ��
	// ��������Ҫ֪������ͻ��˵�ip�������ͨ����s_pid_ip_hash���ҵõ���
	

	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)  //ѭ���ȴ��ӽ����˳�
	{
		--s_children;  //�ӽ��̸�����1
		unsigned int *ip = hash_lookup_entry(s_pid_ip_hash, &pid, sizeof(pid));
		if (ip == NULL)
		{
			continue;
		}

		drop_ip_count(ip);  
		//��������Ѿ��˳��ˣ���ô��pid��ӳ��Ҳû�д��ڵļ�ֵ��
		hash_free_entry(s_pid_ip_hash, &pid, sizeof(pid));
	}

}

unsigned int hash_func(unsigned int buckets, void *key)
{
	unsigned int *number = (unsigned int*)key;

	return (*number) % buckets;
}

unsigned int handle_ip_count(void *ip)  //���ص�ǰip��������
{
	// ��һ���ͻ���¼��ʱ��Ҫ��s_ip_count_hash����������еĶ�Ӧ����,
	// ����ip��Ӧ��������Ҫ��1����������������ڣ�Ҫ�ڱ������һ����¼��
	// ���ҽ�ip��Ӧ����������1��

	unsigned int count;
	//ע�ⷵ�ص��ǵ�ַѽ
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
		*p_count = count;  //д�ص�ԭ��ַ
	}

	return count;
}


void drop_ip_count(void *ip)
{
	// �õ���ip�������ǾͿ�����s_ip_count_hash�����ҵ���Ӧ�����������������м�1������

	unsigned int count;
	//���ص��ǵ�ַѽ���㵱Ȼ���ڶԹ�ϣ����в���
	unsigned int *p_count = (unsigned int *)hash_lookup_entry(s_ip_count_hash,
		ip, sizeof(unsigned int));
	if (p_count == NULL)  //���������ܵ�
	{
		return;
	}

	if (count <= 0)   //���������ܵ�
	{
		return;
	}
	count = *p_count;
	--count;
	*p_count = count;

	if (count == 0)  //��������Ѿ�û�д��ڵļ�ֵ��
	{
		hash_free_entry(s_ip_count_hash, ip, sizeof(unsigned int));
	}
}
