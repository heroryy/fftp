/*************************************************************************
	> File Name: c.c
	> Author: hero
	> Mail: @hero 
	> Created Time: 2022年09月06日 星期二 18时14分11秒
 ************************************************************************/

#include<stdio.h>
#include<sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/file.h>
#include <unistd.h>


int main(){
	int fd=open("tt.txt",O_RDONLY);
	printf("%d\n",fd);
	struct flock the_lock;
	memset(&the_lock, 0, sizeof(the_lock));
	the_lock.l_type = F_WRLCK;
	the_lock.l_whence = SEEK_SET;
	the_lock.l_start = 0;
	the_lock.l_len = 0;
	int ret=0;
	do
	{
		ret = fcntl(fd, F_SETLKW, &the_lock);
	}
	while (ret < 0 && errno == EINTR);
	char* buf[8888]={0};
	read(fd,buf,8888);
	printf("%s\n",buf);
	sleep(100);
}
