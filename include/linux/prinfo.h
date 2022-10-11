#ifndef _LINUX_PRINFO_H
#define _LINUX_PRINFO_H

#include <linux/types.h>

struct prinfo {
	pid_t parent_pid;	/* process id of parent */
	pid_t pid;		/* process id */
	uid_t uid;		/* user id of process owner */
	char comm[16];          /* name of program executed */
	int level;
};

#endif /* _LINUX_PRINFO_H */

