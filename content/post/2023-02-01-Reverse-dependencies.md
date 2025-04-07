---
title: "Reverse dependencies"
subtitle: "Dependencies are like pets, they bring joy but also require constant attention."
date: 2023-02-01T19:15:12+03:00
tags: ["openSUSE","SLES","SUSE", "Linux", "opens source", "zypper", "hackweek"]
type: post
---

### As start let's sort it out what is dependency and what is reverse dependency.

Dependencies and reverse dependencies in Linux distributions are important concepts to understand. A package dependency means that another package relies on it in order to function. For example, if package B requires package A to be installed in order to work, then package B is dependent on package A and is considered a reverse dependency of package A.

Reverse dependencies are important to consider when installing or upgrading packages, as it could impact the functionality of other packages on the system. For example, if package A is upgraded and its API changes, it may cause package B to stop working. Checking the reverse dependencies before installing or upgrading a package can help avoid these issues.

Package managers, such as zypper, can help answer questions about package dependencies. They can also automatically handle package dependencies when installing new packages. For example, if you want to install a package with zypper, it will tell you if it needs to install other packages as well. To list the dependencies of a package, you can use the following command:

```
zypper info --requires <package-name>

```

Things get interesting when we update a package and want to know what other packages we may brake with that update.  Up until the 1.14.33 version of zypper it was a rather difficult question. But then came the fix to provide reverse search in zypper.

If we want to know what packages depend on a given package, we can use the following command:

```
zypper se --requires-pkg <package-name>

```

Using the `--no-refresh` and `--match-exact` options can provide faster and more accurate results.

### Going back to our example

Wwhere package B requires package A to be installed, after both B and A are installed, an update for A is received. The update process does not inform us of which packages may be impacted by installing the new version of A. Hence, we have to run the command `zypper info --requires` ourselves to find out what packages (let's call them B1, B2, ..., Bn) we need to keep an eye on when updating package A. But what about the packages that depend on B1, B2, ..., Bn? Should we not keep an eye on them too? It depends on how cautious we want to be and how well we want to prepare for the worst case scenario. In that case, we need to run the `zypper info --requires` command for each of the B packages (B1, B2, ..., Bn) and discover the packages C1, C2, ..., Cn that depend on them. And the same process should be repeated for the C packages and their reverse dependencies.

A very simple and straight forward implementation in Python to walk the whole reverse dependency tree of any package is available here: [https://github.com/bzoltan1/rdepends](https://github.com/bzoltan1/rdepends)

It is really not a rocket science. A very basic recursive function to climb up the reverse dependency tree as long as it finds all the packages what nothing else depends on.


### Knowing the reverse dependencies of packages has other benefits as well. 
For example, we can assign a weight value to each package in SLES or openSUSE distributions based on the number of packages that depend on it. The more packages discovered in a reverse dependency tree, the higher the impact an update could have. This information can be valuable when planning maintenance updates.

From the point of distribution hygiene, it can also be interesting to observe the growth of reverse dependency trees and compare this growth across different distributions. Understanding the dependency and reverse dependency trees can help us identify areas for improvement.


