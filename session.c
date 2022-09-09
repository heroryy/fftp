#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"

void begin_session(session_t *sess)
{
	//�����׽���fd���մ������ݵĹ���
	activate_oobinline(sess->ctrl_fd); 
	/*
	int sockfds[2];
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0)
		ERR_EXIT("socketpair");
	*/

	//����׽����ڵ�ǰ���̾������Լ��ı��ˣ��Ը�����ûӰ�죬дʱ���ƣ�������
	priv_sock_init(sess);  //sockpair���һ��ͨ�ŵ��׽���

	pid_t pid;
	pid = fork();   //�������ӽ���(�������)
	if (pid < 0)
		ERR_EXIT("fork");

	if (pid == 0)
	{
		// ftp�������
		/*
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		*/

		//��Ϊ���Ǹ��ӽ���ģ�͡�session�Ǳ��̳еģ��������ǵ��ӽ����ǲ���Ҫsess->parent_fd�ġ�
		//���Խ�����Ϊ-1��
		//��������ø�����������Ҳ��ͬ��
		priv_sock_set_child_context(sess); //�����ӽ���������
		handle_child(sess);   //������̿�ʼѭ������ͻ���������������
	}
	else
	{

		// nobody����
		
		/*
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		*/
		priv_sock_set_parent_context(sess); //���ø�����������

		handle_parent(sess);  //��ʼ��Ϊnobody����ĬĬ�ػ����ӽ��̿�
	}
}