---
title: "Setup a Blog With Github Pages and Hugo"
subtitle: "Always be yourself. Except if you can be Batman, then be Batman!"
date: 2021-04-05T19:36:57+03:00
tags: ["hugo", "github", "workflow", "pages","website","opensuse"]
type: post
---
GitHub pages are super powerful and very easy to use for creating markdown based static websites.

In this post I will walk through how I made this very page.

My setup will be two GitHub repositories, one for the source of the page ([https://github.com/bzoltan1/blog-source](https://github.com/bzoltan1/blog-source)) and the other where the html artifacts are deployed ([https://github.com/bzoltan1/bzoltan1.github.io](https://github.com/bzoltan1/bzoltan1.github.io))

Here I would like to note that it is possible to use a single repository with two branches, one for holding the the source and the other where the website is deployed. I just personally find the two repository setup more elegant without any particular reason.

### Prerequisites 

Account on GitHub [https://github.com/bzoltan1/](https://github.com/bzoltan1/)

Git client installed

```bash
sudo zypper install git-core
```

hugo application installed

```bash
sudo zypper install hugo
```

### Create and configure the hugo page and source repository

To start I have created the draft page source with hugo and pulled in the beautifulhugo theme as submodule.

```bash
hugo new site blog-source
cd blog-source
git init
git submodule add https://github.com/halogenica/beautifulhugo.git themes/beautifulhugo
```

At that point I used the instructions ([https://kalikiana.gitlab.io/post/2021-02-12-setup-gitlab-pages-blog-with-hugo/](https://kalikiana.gitlab.io/post/2021-02-12-setup-gitlab-pages-blog-with-hugo/)) from Chris and even used his config.tml ([https://gitlab.com/kalikiana/kalikiana.gitlab.io/-/blob/master/config.toml](https://gitlab.com/kalikiana/kalikiana.gitlab.io/-/blob/master/config.toml)) as template to create mine.

It is really easy to test drive locally the website by running the hugo server

```bash
hugo server
```

and open [http://localhost:1313/](http://localhost:1313/) in the browser. I simple opened an other terminal and adjusted, extended the source tree and refreshed the page in the browswer. As long the hugo server is running it will watch the source tree.

After I was happy with the initial state of the website I have pushed the code to the source repository

```bash
branch -M main
git remote add origin git@github.com:bzoltan1/blog-source.git
git add .
git commit -m "Initial commit" -a
git push -u origin main
```

### Create and configure the GitHub page

Created a vanilla GitHub repository without any content [https://github.com/bzoltan1/bzoltan1.github.io](https://github.com/bzoltan1/bzoltan1.github.io)

As I am going to automatically deploy the website from one repository to the other repository of the GitHub page I need to setup secure authentication

First I created a private/public key pair

```bash
$ ssh-keygen -t rsa -b 4096 -C "$(GIT USER EMAIL)" -f master -N ""
```

It will create the master/master.pub key pair.

I have added the private key as a secret to the hugo source repository

In my case here [https://github.com/bzoltan1/blog-source/settings/secrets/actions](https://github.com/bzoltan1/blog-source/settings/secrets/actions)

The place on GitHub is the Repository -> Settings -> Secrets -> Add new secrets and the name the secret I set ACTIONS\DEPLOY\KEY and pasted the contents of `master` file in the value.

Then added the public key as deployment key in the GitHub pages repository

In my case it is here [https://github.com/bzoltan1/bzoltan1.github.io/settings/keys](https://github.com/bzoltan1/bzoltan1.github.io/settings/keys)

The place on GitHub is the Repository  -> Settings -> Deploy Key -> Add new deploy key 

I have set the "Public Key for the site deploy" as title and pasted the contents of`master.pub`file in the value.

From that point there is nothing to do with that repository. I can browse the html code of the website and if needed I can push there changes. But that would not make much sense as I use GitHub actions to automatically deploy the website when a new version is pushed to the source repository.

I went to the Actions section in the source repository here [https://github.com/bzoltan1/blog-source/actions](https://github.com/bzoltan1/blog-source/actions) and created a new workflow.

The action will be stored in a yaml file under the source tree .github/workflows/ folder: [https://github.com/bzoltan1/blog-source/blob/main/.github/workflows/pages.yml](https://github.com/bzoltan1/blog-source/blob/main/.github/workflows/pages.yml)

I paste here the action yaml file:
```yaml
name: hugo publish

on:
  push:
    branches:
    - main

jobs:
  build-deploy:
    runs-on: ubuntu-18.04
    steps:
    - uses: actions/checkout@v1
      with:
        submodules: true

    - name: Setup Hugo
      uses: peaceiris/actions-hugo@v2
      with:
        hugo-version: '0.59.1'

    - name: Build
      run: hugo --minify

    - name: Deploy
      uses: peaceiris/actions-gh-pages@v2
      env:
        ACTIONS_DEPLOY_KEY: ${{ secrets.ACTIONS_DEPLOY_KEY }}
        EXTERNAL_REPOSITORY: bzoltan1/bzoltan1.github.io
        PUBLISH_BRANCH: master
        PUBLISH_DIR: ./public
      with:
        emptyCommits: false
        commitMessage: ${{ github.event.head_commit.message }}
```

Note few important details here. 

As I am using the beautifulhugo theme as submodule, it is necessary to tell the action that it needs to update that submmodule with the "submodules: true". Aslo remember to hook on the action  to the same branch where you push the source. In my case it is the main branch. The of course I needed to set the deployment environment properly. So the ACTIONS\_DEPLOY\_KEY, EXTERNAL\_REPOSITORY and PUBLISH\_BRANCH should be correct.

### Workflow to create new posts

There are several good ways to create new content. I prefer to use the native hugo way in command line

```bash
$ hugo new posts/\[YYYY-MM-DD\]-\[TITLE\].md
```

Then I  simple edited the created markdown file with vi and fixed the header to have nice tags and changed the "draft:true" to "type: post"

```yaml
---  
title: "Setup a Blog With Github Pages and Hugo"  
date: 2021-04-05T19:36:57+03:00  
tags: ["hugo", "github", "workflow", "pages","website","opensuse"]  
type: post  
---
```

After I have edited the markdown file, all I needed to to do is committing and pushing the code to the source repository and let the GitHub CI do its job. 

```bash
$ git add post/2021-04-05-setup-a-blog-with-github-pages-and-hugo.md
$ git commit -m "New blog post" post/2021-04-05-setup-a-blog-with-github-pages-and-hugo.md
$ git push
```

### What's next?

*   Naturally if  want to reach broader audience getting syndicated is a good way. Chris covers it very well: [https://kalikiana.gitlab.io/post/2021-02-12-setup-gitlab-pages-blog-with-hugo/#can-i-get-that-syndicated-please](https://kalikiana.gitlab.io/post/2021-02-12-setup-gitlab-pages-blog-with-hugo/#can-i-get-that-syndicated-please)
*   Also I would like to know how many readers my posts reach. Google Analytics is a good tool for that
*   But most importantly I would like to recruit more geekos to start publishing their thoughts, ideas and opensource practices
