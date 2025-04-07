---
title: "Telegram Bridge"
subtitle: "Who reads system logs anyway?"
date: 2021-04-05T19:36:57+03:00
tags: ["telegram", "golang", "packaging", "linux", "opensuse"]
type: post
---

### Motivation

I got lucky with my original hackweek project and I have managed to set up my Leap 15.3 based NAS and private cloud running on NextCloud earlier than planned.

So I though that as an extra project I will set up a proper system monitoring service. The monit service is very handy (thanks for the idea to Paolo Stivanin) but by default it wants to send emails when something goes wrong. Instead of emails I would prefer a real instant message. I am using mostly Telegram for personal purposes. Sure I am using Signal, Matrix, Slack and Rocket.Chat too and technically I have WhatsApp account too. But I decided to start with Telegram.

Installing and configuring monit was easy and quick. The monit is using so called alert where it can execute any shell command.

### Idea

I am not very good log reader and I do not like emails that much so I need a Telegram bridge what take messages from anywhere and send messages to me. 

The requirement that my bridge can take messages from anywhere is the most important one. I was considering to open a fifo in /tmp space what processes or scripts can write, but I did not find that solution very elegant one. So I decided that I will start a http server what accepts POSTs via a super simple REST API. That sounded very clean solution. As python, shell scripts or even a simple curl command can feed data to an http server. The test command should be something like this:

`curl --request POST --data '{"sender":"curl","content":"Message content"}' http://localhost:10000/send`  
That should result a Telegram message in my pocket ina format of "curl: Message content"

I do not expect that server to store or handle the message in any way. Just process the POST record and pass it to Telegram.

Naturally I would expect such bridge to work as systemd service and being properly packaged for openSUSE Leap 15.X and Tumbleweed.

### Implementing the bridge

After a short consideration I decided to use golang for implementing the bridge functionality. I could use Python too, but for a system service go is more elegant in my opinion.

I picked the modules I need for the job

*   github.com/go-telegram-bot-api/telegram-bot-api - for interfacing Telegram
*   gopkg.in/yaml.v2 - for processing the configuration file
*   encoding/json - for handling the simple REST API for handling the POST commands
*   github.com/gorilla/mux - for hooking in the Telegram messaging function with the POST commands
*   net/http  - to start the http server

The initial quick and dirty implementation is very simple, short: [https://github.com/bzoltan1/tgb/blob/main/tgb.go](https://github.com/bzoltan1/tgb/blob/main/tgb.go)

### Packaging

As I was planning to deploy this service on my openSUSE Leap 15.3 based NAS / NextCloud server I needed an rpm package for  Leap 15.X, and as my main workstation is openSUSE Tumbleweed where I test my code I needed also Tumbleweed package.  
This requirement sounds simple but for a novice golang coder it proved to be an interesting challenge.

Handling golang dependencies is a funny exercise. I must say that  if there something I find strange in golang it is how dependencies are worked out. The reason may be that I am an old school distro hacker and I grew up with the attitude that  packaged shared libraries are the way to serve developers and solve dependencies. In a classic Linux distro you have build time package dependencies and run time package dependencies.  But because Linux distros are rolling slow for the need of hipster hackers they worked out their language specific ways of solving dependencies. CPAN library for Perl, pip package management for Python, RubyGems for Ruby and so on. For golang it is the same idea. If your code needs a module  (as mine needed the Telegram API, json and yaml file APIs) then you need to "go get" the modules as build time dependencies. As go builds static binaries, the runtime dependencies are no issues.  
But this "go get" thing is easy only when the development and build and releasing/distributing environment are the same.  As I wanted to build my package on OBS ([https://build.opensuse.org/](https://build.opensuse.org/)) I needed to make sure that my sub 100 line code builds on OBS too. As one can imagine, the build systems seldom allow source packages to pull modules, libraries from the Internet. That would be a horrible security hole in the build system. So a source package can build time depend only on packages what are available in the distribution's repository or on modules (from external vendors) embedded in the source tree.

This is a classic distro repository versus language specific package repository issue what could be a topic of a very long blog post.  Many of the Python, Perl and Ruby modules available in their own language specific package management are actually packaged in rpm and deb format in openSUSE, Fedora, Debian and Ubuntu. So source packages often can simple build depend on these packages. With go it is very different. Almost no go modul is packaged in Linux distros for an understandable reason. Packaging is difficult and slow work. Once a go module would be packaged, tested and released to a distro the upstream module may be developed further and there would be an API break between the packaged module and between the module what can be pulled by a simple "go get".

Long story short, when you package an application written in go you need to embed all the go dependencies to the source package.

The fun part is that with different go versions it can be done in different ways.

The way how it is custom with go available on Tumbleweed is different what is supported with go version on Leap 15.0.

The new and recommended way is documented on these links:

*   [https://golang.org/src/README.vendor](https://golang.org/src/README.vendor)
*   [https://golang.org/ref/mod](https://golang.org/ref/mod)
*   [https://blog.golang.org/using-go-modules](https://blog.golang.org/using-go-modules)

While the old custom is to use the godep tool

*   [https://github.com/tools/godep](https://github.com/tools/godep)
*   [https://www.ardanlabs.com/blog/2013/10/manage-dependencies-with-godep.html](https://www.ardanlabs.com/blog/2013/10/manage-dependencies-with-godep.html)
*   [https://devcenter.heroku.com/articles/go-dependencies-via-godep](https://devcenter.heroku.com/articles/go-dependencies-via-godep)

I would go with using go mod as it is the recommended and default way of handling external vendor modules and dependencies. But as my goal is to provide rpm package for Leap 15.3 I need to comply with the OBS requirements. Needless to say that a binary distributed in rpm package built on Tumbleweed is not compatible with the Leap release as on Tumbleweed the glibc is on 2.33 version while on Leap 15.3 it is on 2.31-

For the sake of learning I have implemented both ways

*   With go mod - [https://build.opensuse.org/package/show/home:bzoltan1/tgb?rev=15](https://build.opensuse.org/package/show/home:bzoltan1/tgb?rev=15)
*   The godep - [https://build.opensuse.org/package/show/home:bzoltan1/tgb?rev=18](https://build.opensuse.org/package/show/home:bzoltan1/tgb?rev=18)

The solution based on godep works in both case so I have left the trunk using that: [https://build.opensuse.org/package/show/home:bzoltan1/tgb](https://build.opensuse.org/package/show/home:bzoltan1/tgb)

### What is next

*   I should implement some more protocols, Matrix is the next and then Slack and Rocket.Chat. Contributions are welcome
*   It would be fun to figure out if there is need for such service in the openSUSE distro
