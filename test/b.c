/*************************************************************************
	> File Name: b.c
	> Author: hero
	> Mail: @hero 
	> Created Time: 2022年09月06日 星期二 17时05分54秒
 ************************************************************************/
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
int main() 
{
    struct passwd *pw;
    char *username = "atguigu";
    pw = getpwnam(username);
    if (!pw) {
        printf("%s is not exist\n", username);
        return -1;
    }
    printf("pw->pw_name = %s\n", pw->pw_name);
    printf("pw->pw_passwd = %s\n", pw->pw_passwd);
    printf("pw->pw_uid = %d\n", pw->pw_uid);
    printf("pw->pw_gid = %d\n", pw->pw_gid);
    printf("pw->pw_gecos = %s\n", pw->pw_gecos);
    printf("pw->pw_dir = %s\n", pw->pw_dir);
    printf("pw->pw_shell = %s\n", pw->pw_shell);
}
