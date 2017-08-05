# Book Introduction

Automation. It's a word that strikes fear into some people and delight into others. In the mainstream, it has unfortunately become synonomous with removing humans from jobs with robots. But, automation is here not to directly take peoples' jobs. It's sole purpose is to remove necessary tasks that humans used to do so that humans can perform tasks that require more creative work. In the IT world, automation is all around us whether we realize or not. We use software every day that obfuscates what it _really_ takes to get a job done. And with the introduction of scripting, we can build our own systems on top of existing software and services to make our daily work lives even easier!

## Writing Code is the Easy Part

One of the hardest parts to convey to someone new to scripting is that writing the actual code is, by far, the easiest part of automating a task. On the surface, this statement sounds crazy to someone new to a language, like PowerShell for instance. They see all of this code and immediately get that deer in the headlighsts look. They think that the code _is_ the automation. That sentiment has some merit but it's not the whole picture.

Automating any task, regardless if it has something to do with IT or not, first requires a thorough understanding of the process. A prerequisite for any automation task large or small first and foremost requires a detailed understanding of the task at hand. This may sound obvious and it is in some situations but most people that have been performing a manual task for years have never really sat down and documented each piece that's required to see something to completion. Companies may have some kind of manual documentation but it's rarely up to date and 100% accurate. There's usually minor steps that must be done that exist only in someone on the team's head that never goes into the documentation (if there is any to begin with).

Writing code to automate a task is the easy part. It's breaking down that task into tiny, understandable bits and documenting that repeatable process that's hard. If you find yourself getting discouraged with a script think to yourself first, "Do I thoroughly understand what I'm trying to accomplish"? If the answer is no, the problem doesn't exist with the code language. The problem is that you jumped into coding too quickly without comprehending the task beforehand.

## Automating with PowerShell

After being introduced in November of 2006, PowerShell has since took off like a gun. PowerShell is a language that succeeded VBscript (Microsoft's previous attempt at a scripting language). It's easy to understand syntax made it popular amongst many IT professionals. Windows PowerShell finally made "coding" accessible to anyone that didn't write code for a living. It introduced many IT professionals to the concept of code and quickly rose in popularity over the old VBscript language.

Microsoft has went all in with PowerShell. The company now has PowerShell support for never every product they produce. It's never been easier to automate all kinds of products like Exchange, Active Directory, Hyper-V and dozens of other Microsoft products. However, PowerShell is not just for Microsoft products alone. PowerShell is flexible enough to interact with every Microsoft product and also with thousands of other products through a number of different means. PowerShell can be thought of as "automation glue". It's the language that can bring various services and technologies together to work in tandem to complete a task.

Automating with PowerShell is a fun experience whether you're just starting out or you're a seasoned scripter.

## Who this Book is For

This book is for anyone in IT that has ever performed a task for the nTh time and thought, "There's got to be better way to do this". The book is for IT professionals, software developers, database administrators, storage engineers or network engineers that want to get more done at work with less effort. We're looking for "lazy" people here. This book is for people that would rather run a script and go to lunch rather than spending an hour clicking around multiple windows, making mistakes that require performing the same step again and fumbling their way through a process they've done a hundred times before.

This book is for people that are always looking for ways to improve. Really "getting" automation and scripting is something that's learned and will take some time to truly understand the power of automation. The book is for those that not only love saving time but also love building things. It's for those people that love putting in the work to see the fruits of their labor and it's ultimately for anyone that may be interested in writing scripts or simply use to leverage automation through PowerShell.

## Prerequisite Knowledge

We're going to assume if you've picked up this book that you might of at least heard of PowerShell and have a vague idea of what it is. That's all we're going to need from you. We're going to take you from knowing absolutely nothing about automating with PowerShell all the way up to automating some complex procedures.

You're expected to have a working knowledge of the Windows operating system such as the file system, the registry, event log, Windows Management Instrumention (WMI) along with some common Windows server services like Internet Information Services (IIS), SQL Server, Active Directory and so on. You're not expected to be an expert in any of these technologies but if you understand that the registry has keys, the event log has messages, IIS is a web server and SQL Server holds databases, that's good enough for us.

We're essentially assuming you're an IT professional with a little bit of experience in the field.

## Chapters

### Part I

Part I will be all about just getting comforable with PowerShell. We'll kick the tires and cover the basics. In Part I, we will not teach you everything there is to know about PowerShell nor everything about the project we'll eventually be building. We'll rather give you the knowledge you need to learn more on their own. In this part, we'll be creating small scripts from each chapter where applicable. At the end of each chapter, we'll have a script that demonstrates how all of the concepts you've learned in that chapter fit together.

If you're an intermediate PowerShell scripter or expert, it's OK to skip this part and get right to Part II.

### Chapter 1: Exploring Commands

This chapter will introduce the concept of cmdlets in PowerShell. We'll use the Get-Command cmdlet mostly to discover what cmdlets are available on a system and briefly cover the concept of modules as containers for commands. We'll discover how PowerShell treats commands, their naming convention and how to find commands.

### Chapter 2: Getting Help

This chapter will explain how the PowerShell help system works. We'll cover how to use the Get-Help command to find information about various cmdlets and about topics. We'll also cover how PowerShell's Update-Help command works to get the latest help content.

### Chapter 3: Working with the Pipeline

This chapter will introduce a feature that makes PowerShell unique; the pipeline. We'll briefly cover the concepts of objects in PowerShell and how commands send objects out through the pipeline and how those objects are received from the input command.

### Chapter 4: Working with Variables

This chapter will explain how to create, read and remove variables in PowerShell. We'll also cover the Variable PowerShell drive so discover all variables that are created at a certain time.

### Chapter 5: Combining Commands into Scripts

In previous chapters, we haven't even built a script yet. We've been using the console and inputting commands. In this chapter, we'll be stringing those commands together in a single executable script. We'll go over recommended script editors, how to invoke scripts and how scripts can be maintained.

### Chapter 6: Building Functions and Modules

In this chapter, we'll take our PowerShell expertise a step further and focus on PowerShell functions and modules. We'll explain how functions work in PowerShell, go over how to use convert scripts into functions, how they are similar and then define and build our first PowerShell module.

### Chapter 7: Working with the Registry

This chapter will cover everything we'll need to know about reading, creating and modifying various registry elements with PowerShell. We'll introduce the PowerShell registry provider and cover managing registry keys and values within the various registry PowerShell drives.

### Chapter 8: Working with the File System

This chapter will dovetail off of the Registry chapter because the file system uses a PS drive as well. We'll explain that navigating and manipulating the file system is very similar to the registry but we're just working with files and folders now instead of keys and values.

### Chapter 9: Working with WMI/CIM

This chapter will introduce WMI/CIM. We'll cover what each of those acronyms mean and their differences. We'll then cover the core read cmdlets in PowerShell Get-WmiObject and Get-CimInstance and show you how to pull information from WMI using these commands.

### Chapter 10: Working with the Event Log

This chapter will go over how to pull information from the event log. We'll cover both the Get-EventLog and Get-WinEvent commands, explain a little about the differences and when to use one over the other.

### Chapter 11: Working with Windows Services

This chapter wil cover all of the basic Windows services cmdlets. We'll go over how to enumerate services, stop and start them as well as how to use the pipeline.

### Chapter 12: Testing PowerShell with Pester

This chapter will cover Pester; a PowerShell module for testing PowerShell scripts that's used for performing tests against both PowerShell scripts and script results. Starting in Part II, we'll be building a Pester test for each section to ensure the code we're writing does what we expect it to.

### Part II

Part II is where the rubber meets the proverbial road. Part II is where we'll take what we've learned in Part I and begin building our project called PowerLab. PowerLab is a project built solely in PowerShell that will bring together hundreds of different elements to provision an entire lab from scratch. In this part, we'll build PowerLab to automatically create virtual machines, install Windows Server on those virtual machines, stand up an Active Directory domain, SQL Server and an IIS web server. In this part, we'll automate building the underlying infrastructure to prepare us for the day-to-day maintenance that will be required to maintain this test lab.

### Chapter 13: Logging

Since the succeeding chapters are all going to be building off of a single tool, we need a way to capture error information and see the results of our progress all in one spot. We need a log file. Ths chapter will go over how to use PowerShell to log information. We'll create a custom Write-Log function that will write to a text file all verbose and error information about the progression of our code.

### Chapter 14: Remotely Managing Computers

This chapter will cover PowerShell remoting. We'll go over what PowerShell remoting is and what's it's used for. We'll demonstrate how to get PowerShell remoting setup on both the client and a server along with the various ways PowerShell remoting can be configured.

### Chapter 15: Working with Virtual Machines

This chapter we'll begin creating Hyper-V virtual machines. We will look to the future chapters to understand just how many VMs we need and set out creating a function that will do this for us.

### Chapter 16: Automating Operating System Installs

This chapter will work off the previous chapter and show the reader how to take the VMs we created before and setup a function in our module to automagically deploy Windows to each VM.

### Chapter 17: Working with Windows Features

This chapter we'll look to the future chapters to figure out what kind of Windows features needs installed to make our tool possible. We'll go over how to enumerate Windows features and add them at will.

### Chapter 18: Creating an Active Directory Forest

This chapter will show the reader how to promote a VM to a domain controller creating a forest. We'll introduce the ActiveDirectory module, how to use various commands in there and then how to create a plain DC from scratch.

### Chapter 19: Installing and Configuring IIS

This chapter will show the reader how to install IIS, create websites and app pools.

### Chapter 20: Installing and Configuring SQL Server

This chatper will show how to use PowerShell to automate a SQL server installation and perform some basic configuration on it to get the groundwork setup.

### Part III

Part III is where we'll focus on maintaining our test environment. We'll focus on using the services we deployed in Part II to mimic real-world day-to-day tasks. This part is where we'll focus on populating it with services that end users will need, ensuring the environment stays up to date and more.

### Chapter 21: Working with Active Directory

This chapter we'll again use the ActiveDirectory module but this time populate our domain with users, OUs and groups. We'll use a CSV file full of information and show the reader how to use a CSV file to sync all of this information to an Active Directory domain rather than hardcoding all of this information.

### Chapter 22: Working with IIS

This chapter is where we'll create a super-basic website. We'll do this by creating a website, an app pool and other basic tweaks to serve up a basic web page.

### Chapter 23: Working with SQL

This chapter is where we'll populate the SQL server created earlier with a database, SQL users and other SQL objects. We'll cover how to create tables, execute various queries and more. We'll do this by using a few PowerShell modules but briefly talk about the technologies like SMO most of these modules use to interact with SQL Server.

### Chapter 24: Automating Software Deployments

This chapter is where we'll create functionality to deploy MSIs to our machines. We'll create a function called Install-Software that will take an existing MSI and push it out to the targeted machines using just the MSI name and the names of the target computers.

### Chapter 25: Automating Windows Updates

This chapter is where we'll show how to push out required Windows updates to our test environment we've created already. We'll show how to use a community module created by myself to enumerate installed Windows updates and then install and reboot machines that need any updates installed.

### Part IV

By Part IV, we've got a fully-funcitoning environment that resembles a real-world experience with an Active Directory domain, SQL databases and a web server. We've been keeping it up to date and active for our users and now it's time to start periodic monitoring. In this part, we're going to build the tools necessary to setup continual monitoring of the environment to ensure it stays how it was built. We'll build a few tools to periodically test our environment against known good states, report the results and finally send notifications to ensure we know about any potential problems.

### Chapter 26:Automating Common Server Checks

This chapter we'll start building the monitoring tool by showing the reader how to query information from all our machines at once. We'll focus on common statistics like pulling hard drive space, memory, operating system, etc and creating functionality that will setup us up for building an HTML report in the next chapter.

### Chapter 27: Generating Reports

This chapter is where we'll take the data gathered from the last chapter and create a color-coded HTML reports that will allow us a dashboard of how our test environment is running and what's running in it.

### Chapter 28: Working with Scheduled Tasks

In the previous chapter, we had to run our report manually to refresh the information. In this chapter, we'll go over how to create scheduled tasks with PowerShell and how to invoke our reporting script on a regular schedule so that our report always stays up to date.

### Chapter 29: Sending Email

This chapter will show how to add notification ability to our reporting/monitoring tool by sending emails. We'll go over how to send emails, attach our report and attach the log files in case an error has occurred.

## Prerequisite Software

To work through all of the demos we'll be working through in this book, we're going to assume you already have the following:

- A Hyper-V hypervisor host with roughly 100GB+ of storage space. You can choose to use the [standalone Hyper-V 2016 server downloadable from Microsoft](https://www.microsoft.com/en-us/evalcenter/evaluate-hyper-v-server-2016) or [install the Hyper-V role on full Windows Server 2016](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server). If you choose to install Hyper-V on a full Windows Server 2016 host, you can [download a 180 day free evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016) of Windows Server 2016 from Microsoft.

- A Windows 10 Pro client on the same network as the Hyper-V host. This will be the workstation we'll be performing all demos and remote work from. Windows 8.1 may work with PowerShell version 5 installed but it was not tested on.

- ISO for Windows Server 2016. An ISO can be [downloaded from Microsoft](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016) for a 180 day free trial.

- ISO for SQL Server 2016. An ISO can be [downloaded from Microsoft](https://www.microsoft.com/en-us/evalcenter/evaluate-sql-server-2016) for a 180 day free trial.

## Book Takeaways

As you digest the material in this book, you're going to roughly learn three different points:

- How to think about automation and what it can do
- How to use PowerShell to implement that thinking
- How to come up with ideas for automation opportunities

First and foremost, as was alluded to earlier, it takes more than simply writing a single script to "get" automation. It's a start but it's not until you begin instinctively breaking down a process into chunks in your head to then automate every time your boss hands you a task is when scripting and automation is in your blood. The book will encourage this. This book will help you realize that every project, task, workflow or action you take in IT can usually be automated in some fashion and help you save time.

To learn how to think about automation and what it can do, you must have an implementation plan. You must have some kind of tool to take an abstract idea like automation and see how it can help. The PowerShell language will be our tool of choice. This won't be a "how to PowerShell" book per se but it will be fairly close simply because to automate any process requires a thorough understanding of the tool you're using.

Finally, and most importantly, the book will help you come up with automation ideas in your own environment. The topics we cover are common to many IT professionals. As we go along and you begin to see what's possible, you'll instinctively begin to see similarties in the topics we cover and the demos we work through to your own environment. Capture those ideas! If you've got a great idea, stop reading the book and explore that idea; at least write it down to come back later. Our IT minds can be fickle so it's important to capture that "aha" moment as it comes along.  This book's whole goal is to show you what's possible. The true learning experience when you take that primer knowledge and begin to apply it in your own world.