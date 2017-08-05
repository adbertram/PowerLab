# Automate the Boring Stuff with PowerShell

## Summary

This book will follow a similar pattern as the _Automate the Boring Stuff with Python_ book. However, instead of using Python as the language of choice, the language will be PowerShell. Python isn't usually associated with Windows administration and working with Microsoft products. PowerShell is usually the choice of lots of IT professionals and system administrators to automate various tasks in a Windows environment.

This book will follow the same pattern at the Python book which first sets out to introduce the language being used in the book and how to perform just enough tasks to get started using it. The first part will not focus on teaching the reader everything there is to know about the language but just enough to get them on their feet to then have the courage to begin trying things out on their own.

The true heart of the book will be in the later parts where we get into automating actual, real-world tasks that can save the reader time.

## Chapters

- Part I - The Basics

Part I will be all about just getting comforable with PowerShell. We'll kick the tires. This part's purpose is to not teach everything there is to know about PowerShell but rather give the reader's the knowledge they need to learn more on their own. In this part, I will be creating a small script in each chapter. Each chapter will work on a different script. At the end of each chapter, the reader will have an executable script that demonstrates how all of the concepts they've learned in that chapter fit together.

    Introduction - 1-2 pages

    This small section will introduce what we'll be doing in this part. It will set clear expectations of what's expected of the reader ahead of time and what the reader should know when they're done reading. It will also tell them that in each chapter, they'll be creating a script that builds off of the concpets they learned in that chapter.

    1. Exploring Commands - 15 pages

    This chapter will introduce the concept of cmdlets in PowerShell. We'll use the Get-Command cmdlet mostly to discover what cmdlets are available on a system and briefly cover the concept of modules as containers for commands.

    2. Getting Help - 15 pages

    This chapter will explain how the PowerShell help system works. We'll cover how to use the Get-Help command to find information about various cmdlets and about topics. We'll also cover how PowerShell's Update-Help command works to get the latest help content.

    3. Working with the Pipeline - 15 pages

    This chapter will inroduce a feature that makes PowerShell unique; the pipeline. We'll briefly cover the concepts of objects in PowerShell and how commands send objects out through the pipeline and how those objects are received from the input command.

    4. Working with Variables - 10 pages

    This chapter will explain how to create, read and remove variables in PowerShell. We'll also cover the Variable PowerShell drive so discover all variables that are created at a certain time.

    5. Combining Commands into Scripts

    6. Building Functions and Modules - 20 pages

    THis chapter will explain to the reader what a function and a module is and how to create basic ones.

    7. Working with the Registry - 15 pages

    This chapter will very briefly explain the concept of a PowerShell drive just enough to make the reader understand the Registry PS Drive. It will show how by using common commands, we can manipulate anything in the registry by using it just like a file system they might be used to.

    8. Working with the File System - 15 pages

    This chapter will dovetail off of the Registry chapter because the file system uses a PS drive as well. We'll explain that navigating and manipulating the file system is very similar to the registry but we're just working with files and folders now instead of keys and values.

    9. Working with WMI/CIM - 20 pages

    This chapter will introduce WMI/CIM. We'll cover what each of those acronyms mean and their differences. We'll then cover the core read cmdlets in PowerShell Get-WmiObject and Get-CimInstance and show the reader how to pull information from WMI using these commands.

    10. Working with the Event Log - 10 pages

    This chapter will show the reader how to pull information from the event log. We'll cover both the Get-EventLog and Get-WinEvent commands, explain a little about the differences and when to use one over the other.

    11. Working with Windows Services - 10 pages

    This chapter wil cover all of the basic Windows services cmdlets. We'll go over how to enumerate services, stop and start them as well as how to use the pipeline. Manipulating services via the pipeline is a great demonstration.

    12. Testing PowerShell with Pester - 20 pages

    This chapter will cover Pester; a PowerShell module for testing PowerShell scripts that's always used to do "infrastructure testing". Pester's main use is unit testing but this is way outside of the scope of this book. I've written an entire other book about that. I'd like to use Pester in this book as an "infrastructure testing" tool to define the required state of items, run code to read that state once created and provide a pass/fail scenario to ensure everything is setup as it should be. At the end of each chapter, we'll be sure to create a new Pester test for each section. At the end of the book, we'll have a test suite that can verify all items in our environments are configured as expected.

- Part II - Building Servers and Services

Part II is where we get down to actually creating a useful, real-world tool. This part is where we'll build a module

    Introduction - 1-2 pages

    This is where we'll be introducing the tool we'll be building throughout parts I and II. Even though the concepts learned in each individual chapter could be useful scripts in of themselves, we're going to start from the point of view where we have this large problem (creating an entire environment) and how we're going to solve it using PowerShell. This introduction will be longer than the first part because we'll be outlining the task at hand and breaking down this task of creating an entire environment from scratch.

    This part will tell the reader we're going to start building a module which will contain all of the functions we need to eventually create an entire environment from scratch using a single command. This will show the reader just how much can be automated with PowerShell and how easy it is to replicate just about anything with a single command.

    1. Logging - 10 pages

    Since the succeeding chapters are all going to be building off of a single tool, we need a way to capture error information and see the results of our progress all in one spot. We need a log file. Ths chapter will go over how to use PowerShell to log information. We'll create a custom Write-Log function that will write to a text file all verbose and error information about the progression of our code.

    2. Remotely Managing Computers - 15 pages

    This chapter will cover PowerShell remoting. It will show the reader how to get it setup on both the client and server, various authentication schemes that can be used and how to execute remote commands.

    3. Working with Virtual Machines - 15 pages

    This chapter we'll begin creating Hyper-V virtual machines. We will look to the future chapters to understand just how many VMs we need and set out creating a function that will do this for us.

    4. Automating Operating System Installs - 15 pages

    This chapter will work off the previous chapter and show the reader how to take the VMs we created before and setup a function in our module to automagically deploy Windows to each VM.

    5. Working with Windows Features - 10 pages

    This chapter we'll look to the future chapters to figure out what kind of Windows features needs installed to make our tool possible. We'll go over how to enumerate Windows features and add them at will.

    6. Creating an Active Directory Forest - 20 pages

    This chapter will show the reader how to promote a VM to a domain controller creating a forest. We'll introduce the ActiveDirectory module, how to use various commands in there and then how to create a plain DC from scratch.

    7. Installing and Configuring IIS - 15 pages

    This chapter will show the reader how to install IIS, create websites and app pools.

    8. Installing and Configuring SQL Server - 20 pages

    This chatper will show how to use PowerShell to automate a SQL server installation and perform some basic configuration on it to get the groundwork setup.

- Part III - Automating Day-to-Day Management Tasks

    1. Working with Active Directory - 15 pages

    This chapter we'll again use the ActiveDirectory module but this time populate our domain with users, OUs and groups. We'll use a CSV file full of information and show the reader how to use a CSV file to sync all of this information to an Active Directory domain rather than hardcoding all of this information.

    2. Working with IIS - 20 pages

    This chapter is where we'll create a super-basic website. We'll do this by creating a website, an app pool and other basic tweaks to serve up a basic web page.

    3. Working with SQL - 20 pages

    This chapter is where we'll populate the SQL server created earlier with a database, SQL users and other SQL objects. We'll cover how to create tables, execute various queries and more. We'll do this by using a few PowerShell modules but briefly talk about the technologies like SMO most of these modules use to interact with SQL Server.

    4. Automating Software Deployments - 15 pages

    This chapter is where we'll create functionality to deploy MSIs to our machines. We'll create a function called Install-Software that will take an existing MSI and push it out to the targeted machines using just the MSI name and the names of the target computers.

    5. Automating Windows Updates - 10 pages

    This chapter is where we'll show how to push out required Windows updates to our test environment we've created already. We'll show how to use a community module created by myself to enumerate installed Windows updates and then install and reboot machines that need any updates installed.

- Part IV - Server and Network Monitoring

    Introduction - 1-2 pages

    In this introduction, we'll use the test environment created in Part I to move towards a monitoring and management phase. We'll introduce the new tool we'll be creating to monitor the infrastructure here.

    1. Automating Common Server Checks - 20 pages

    This chapter we'll start building the monitoring tool by showing the reader how to query information from all our machines at once. We'll focus on common statistics like pulling hard drive space, memory, operating system, etc and creating functionality that will setup us up for building an HTML report in the next chapter.

    2. Automating Reports - 10 pages

    This chapter is where we'll take the data gathered from the last chapter and create a color-coded HTML reports that will allow us a dashboard of how our test environment is running and what's running in it.

    3. Working with Scheduled Tasks - 10 pages

    In the previous chapter, we had to run our report manually to refresh the information. In this chapter, we'll go over how to create scheduled tasks with PowerShell and how to invoke our reporting script on a regular schedule so that our report always stays up to date.
    
    4. Sending Email - 10 pages

    This chapter will show how to add notification ability to our reporting/monitoring tool by sending emails. We'll go over how to send emails, attach our report and attach the log files in case an error has occurred.


## Audience

The audience is me. This is a book that I would have loved to have when starting out with PowerShell and automation. It is for IT professionals, system administrators and anyone working in a Windows environment that has too many fires to put out and not enough time.

It is for the jack of all trades IT pro that has to automate as much as possible to keep up with his work. It's about showing people that may not automate much now that if they think of automation first, PowerShell can help them tremendously in their jobs.

## Competition

- PowerShell in a Month of Lunches
  - https://www.amazon.com/Learn-Windows-PowerShell-Month-Lunches/dp/1617291080
- Learn PowerShell Toolmaking in a Month of Lunches
    - https://www.amazon.com/Learn-PowerShell-Toolmaking-Month-Lunches/dp/1617291161
- Windows PowerShell Best Practices
    - https://blogs.msdn.microsoft.com/microsoft_press/2014/01/20/new-book-windows-powershell-best-practices/

## Market

The market for this book is large. There are _lots_ of system administrators out there that are in charge of managing Windows servers and products by Microsoft. Many of those system administrators have also not yet fully realized what an automation mindset and PowerShell can do for them.

Microsoft has been pushing PowerShell hard and nearly 100% of products now have native PowerShell support. PowerShell was also built to be a universal language meaning it can natively control many other services besides Microsoft products as well. I believe the market is every IT professional, helpdesk person or system administrator that controls more than a single server or a single desktop at a time.

## Me

I am a Senior Automation Engineer, independent consultant, technical writer, trainer, and presenter. I specialize in consulting and evangelizing all things IT automation mainly focused around PowerShell. I'm a 3-time Microsoft Windows Cloud and Datacenter Management MVP (2 years being a PowerShell MVP) and have authored various training courses on Pluralsight around PowerShell and am a regular contributor to numerous print and online publications.

My blog is at adamtheautomaotor.com and I'm on Twitter at @adbertram.

Here are links to all of my articles. I've also written an eBook on Pester which is a testing framework for PowerShell here (https://leanpub.com/pesterbook/).

- 4Sysops: https://4sysops.com/archives/author/adam-bertram/
- TIP: http://www.tomsitpro.com/tags/?author=adam+bertram
- CIO.Com: http://www.cio.com/search?query=Adam+Bertram&contentType=article%2Cresource
- InfoWorld: http://www.infoworld.com/author/Adam-Bertram/?nsdr=true
- IpSwitch: https://blog.ipswitch.com/author/adam-bertram
- TechTarget Sites: http://www.techtarget.com/contributor/Adam-Bertram
- RedmondMag: https://redmondmag.com/Forms/Search-Results.aspx?query=Adam%20Bertram&collection=Redmondmag_Web
- McpMag: https://mcpmag.com/Forms/Search-Results.aspx?query=Adam%20Bertram&collection=MCPMAG_Web