---
title: "Checking changelogs with zypper"
subtitle: "The future you see is the future you get."
date: 2022-11-11T11:11:11+03:00
tags: ["openSUSE","SLES","SUSE", "linux", "opens source", "zypper"]
type: post
---

I have heard way to often the question from Linux and specially SUSE Linux users that *"How can I check the changelog of a package or new version of a package available on the repository, but not yet installed"*.

There was no easy answer for that question, so I have decided to make a little tool for that.

### How it is done

All the enabled repositories have a bunch of configuration files in a well structured directory tree under the `/var/cache/zypp/raw/`.

All we need to do is to find the primary.xml.gz of each repository unzipp the file and parse through the xml structe for the packages. 

It is a fairly big file if the repository has lots of packages and it takes some time to process it. 

From this file we can figure what is the direct URL to each package. It is really nice and helpful that the package information contains the location of the rpm header of the package in the rpm file.
This rpm header contains the changelog of the package. Knowing the offset and the size of the rpm header makes it possible to fetch only a small part of each package and so find the changelog.

Looping through the full package list and downloading the rpm header to read the package changelog is still a time consuming process. But so far I could not figure out better way to collect the changelogs of each available packages.

Once the changelogs are downloaded all we need is to compare the changelog of the locally installed version of each package and see the difference. The rpm provides information about the local changelogs: 
```
rpm -q --changelog [full packagename]
```
The full package (consists of the package name with the version number) name we can get from 
```
zypper info [package name]
```

### Where the tool is

The naked tool is available on the [zipper changelog plugin GitHub project](https://github.com/bzoltan1/zypper-changelog-plugin) project. So far I have released it to openSUSE Thumbelweed under the name of `zypper-changelog-plugin`. The package can be installed with 
```
sudo zypper install zypper-changelog-plugin
```


### How does it work

The `zypper changelog [-h]` gives a detailed instruction but basically the tool takes the following parameters:
| Parameter                        | Desscription                                                   |
| :---                             |    :----                                                       |
| -h, --help                       | Show the help message                                          |
| -d, --debug                      | Runs the tool in debug mode.                                   |
| -c, --commits                    | Lists only the headline of the change commits.                 |
| -e, --expression                 | Enable regular expression in package name.                     |
| -p PACKAGES, --packages PACKAGES | Package name or regular expression to match packages.          |
| -r REPOS, --repositories REPOS   | Comma separated list of repositories to search for changelogs. |
| -a, --all                        | Lists changelogs for all available packages                    |
| -u, --update                     | Lists changelogs for all packages to be updated                |


### Simple usecases

- To show all changelog for all packages in the openSUSE-Tumbleweed-Oss repository. This process may take very long time (even hours) depending on how good connection we have to the repositories.

```
$ zypper changelog -a -r repo-oss`
```

- To  show the list contributors of Firefox in the openSUSE-Tumbleweed-Oss repository

```
$ zypper changelog -p MozillaFirefox -r repo-oss -c
```
- To show the changelogs of all vim* packages the openSUSE-Tumbleweed-Oss and binary and source repositories

```
$ zypper changelog -p MozillaFirefox -r repo-oss,repo-source
```

- To show the changelogs of all packages updated on the next zypper up/dup

```
$ zypper changelog -u
```

### Some hints, ideas and disclaimers 

- There is no need to run the tool as root.
- It is important to refresh the local repository cache: $ sudo zypper ref -f
- The best way to see what repositories are enabled on a system is $ zypper -x ls
- The tool is using directly the URL of the repository server. So no mirrors are used.
- It is possible to see all the past contributors of a given package with this tool
- As a single source package can provide several binary packages and each binary package will have the same changelog.
- Be prepared for long execution time even if the connection to the remote repositories are fast.Fetching all the changelogs for openSUSE source repository may take 80-120 minutes.
- The /var/cache/zypp/raw/[REPOSITORY]/repodata/ directory has a *repomd.xml file what points to the *other.xml.gz file. That file is about 25MB and it contains all changelogs for all packages. Downloading and parsing these file may be more efficient when the bandwidth to the servers is low. 
- At the moment the zypper-changelog-plugin is released in openSUSE Tumbleweed but I am working on to enable it on openSUSE Leap and on the SUSE Enterprise Linux Server editions as well.
