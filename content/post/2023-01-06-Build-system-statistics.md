---
title: "Build system statistics"
subtitle: "Okey, let's start with a boring cliché..."
date: 2023-01-06T04:41:11+03:00
tags: ["openSUSE","SLES","SUSE", "linux", "opens source", "osc", "Open Build Service", "LDAP"]
type: post
---

From time to time we should ask ourselves how are we doing. Are we successful, are we on the right track, are we heading to the right direction, are we fast enough, are we accelerating or slowing  down?

This time I am talking about the openSUSE  Linux Distribution and about the SUSE Linux Enterprise Server.

And here I quickly would like to note an important disclaimer with a short story. 

If you blindfold two persons who have never seen an elephant, have them stand in front and behind of the animal and ask them to observe it. The one behind the elephant will reach for the tail and think that the elephant is a thin, lean, bony animal, while the one in front of the animal will reach for the trunk of the elephant and think that it is a muscular, flexible, hose-like animal. Naturally both are terribly wrong. 

Both draw their own conclusion based on the data they have access to.

So, already here I would like to emphasize that the data what I am about to dig up will for sure expose only a part of the truth and even the validity of the data and how the data is collected can be and should be challenged.

### The goal 

The initial question was if we have enough maintainers, bug owners, contributors for the packages in our projects. And if we want to increase the number of contributions how can we measure that we are doing a good job? Also we had the question if our community is diverse enough. And by diversity I mean whether we have a few people who do lots of work or lots of people doing little work.

Also I really want to celebrate contributions and recognize the effort of volunteers who take care of our beloved Linux distribution and the platform what keeps our teams and company running. Without knowing who these people are and where are they "hiding" it is close to impossible to celebrate them.

### Kick off

I started to figure out where the data is, how it can be accessed and processed. Luckily I got help from various people.

Naturally  the starting point is the public API of the [openSUSE Build Service](https://build.opensuse.org/) what can be consumed easily with the `osc` command

For example the list of projects one has access can be obtained by the
```
osc -A https://api.opensuse.org api /source
```

and `grep` is our friend to filter out what we are interested in.

To list all the packages under a given project, for example under the openSUSE:Tumbleweed the osc command is this:

```
osc -A https://api.opensuse.org api /search/package/id?match=@project+%3D+%27openSUSE:Tumbleweed%27
```

To figure out who is maintaining a package the command is:

```
osc -A https://api.opensuse.org api /search/owner?package=zypper-changelog-plugin
```

Yay! I see my own record :)

But that record tells only the user name on the build server. To get the real name and email address:

```
osc -A https://api.opensuse.org whois bzoltan1
```

what will return `bzoltan1: "Zoltan Balogh" <zbalogh@suse.com>`

This is basically how we find the maintainers/bugowners and we can ask about specific bugs, upcoming updates. If we do this whole exercise with the SUSE Enterprise Linux and the maintainer has suse.com email address then we can look up the maintainer in internal tools.

### The real deal

So we have all the APIs and tools at our disposal to mine the build service. I could have created a shell script to wrap these `osc` command line calls and do some magic with the output, but I think there is a more elegant way to do the job.

And here I would like to give credit to the developer of the [osc-tiny](https://osc-tiny.readthedocs.io) API developer,  [Andreas Hasenkopf](https://github.com/crazyscientist) who made it possible to access the [API](https://build.opensuse.org/apidocs/index) of any Open Build Service instance from python. It is a really nice implementation with clean and easy to understand manual. Also Andreas was kind and patient enough to help me when I got blocked during development.


Basically I could easily write a python script what does all these steps from above auto-magically and produces a both human and program readable out. The code is available here: [https://github.com/bzoltan1/bs-stat](https://github.com/bzoltan1/bs-stat)

Kudos and thanks to [Andrea Manzini](https://github.com/ilmanzo) who contributed the caching and several important improvements to the code. It is always nice to collaborate.

To try out the code one needs to git pull it and  create a `.env` file following the instructions of the [README](https://github.com/bzoltan1/bs-stat/blob/main/README.md). Basically we need credentials for the build server, the address of the AP and a project name and we are ready to rock and roll.

```
./bs-stat.py  > openSUSE_Factory.txt
```


The result is a long text file with the list package names and all the roles arranged in an array with real name and email address. From that point it is a simple CLI exercise to count whatever we are interested in.


For example it shows that there are 866 different individuals with either bugowner or maintainer role in the 14771 packages of the Tumbleweed Factory.

There are 126 different contributors who are responsible for more than 20 packages. And the most popular first name is Stefan. Well, that is not a very valuable information. But the information of how large is the packaging community and how high load individual contributors take is a relevant one. We can and in my opinion we should work on growing this community and collaborate with those contributors who are carrying often 100+ packages on their shoulders.

### Next

As mentioned above mining the build system may expose interesting details about the dynamics of how packages are maintained in projects hosted by an Open Build Service but by no mean it provides full visibility on how we are doing and what should we do better.  Just recently [Martin Pluskal](https://build.opensuse.org/users/mpluskal) (who is one of the undeniable star of opensSUSE contributors with 220 packages with his name as maintainer or bugowner) pointed out that actually the submitted requests of the projects [https://build.opensuse.org/project/requests/openSUSE:Factory](https://build.opensuse.org/project/requests/openSUSE:Factory) may be a more interesting place to start digging for some gold. 

