---
title: "[Attackdefense.com] Privilege Escalation"
date: 2020-08-30T18:17:00+07:00
draft: false
categories: [
    "Offensive Security",
    "Lab"
]
tags: [
    "Linux","Privilege Escalation"
]
---
## Link
[https://attackdefense.com/challengedetails?cid=2021](https://attackdefense.com/challengedetails?cid=2021)
## Student to Teacher
Find SUID binaries
![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/1.png)

Using ‘Strings’ to view

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/2.png)

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/3.png)

When we run the read-submission file. It will call and run the read-file. Read file is a binary file. We will use the PATH variable method

First create another read-file executable file in / tmp with the content to generate a shell. Then use export to append the $ PATH variable. Then run the read-submission file. Because of the teacher’s suid, when running will generate the teacher’s shell:

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/4.png)

## Teacher to Admin

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/5.png)

We have noticed here that the teacher.tar.gz file in the admin home directory is constantly being changed. I think there will be a crontab or timer to do this. But I can’t find it. This file is continuously updata from the backup folder in the teacher home directory. That is tar. When I add any file in the backup and extract the tar to see it, it will update. Here extract tar using wildcard *. I easily got the admin shell from there:

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/6.png)

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/7.png)

### Refer:
[https://www.soliantconsulting.com/blog/dangers-wildcards-bash/](https://www.soliantconsulting.com/blog/dangers-wildcards-bash/)

[https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/Tar%20commands%20execution](https://github.com/cyberheartmi9/PayloadsAllTheThings/tree/master/Tar%20commands%20execution)

[https://coreos.com/os/docs/latest/scheduling-tasks-with-systemd-timers.html#:~:text=service%20every%2010%20minutes.,timer%20to%20enable%20timer.](https://coreos.com/os/docs/latest/scheduling-tasks-with-systemd-timers.html#:~:text=service%20every%2010%20minutes.,timer%20to%20enable%20timer.)

## Admin to Root
![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/8.png)

LD_PRELOAD

![image](https://raw.githubusercontent.com/l3mnt2010/Blog_Image/master/Attackdefense.com-Privilege%20Escalation/9.png)

## Break out of the container
Using Sys module. Insert module to kernel. Create reverse-shell to outside:
### Refer:
[https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)