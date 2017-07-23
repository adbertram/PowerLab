## Find all available commands

Get-Command

## Verb/Noun syntax

## Runing commands

Get-Service
Get-Process

## Running commands with parameters

Get-Service -Name 'wuauserv'
Get-Process -Name 'explorer'

## Aliases
Get-Command -Type Alias

## Cmdlets
Get-Command -Type Cmdlet

## Functions
Get-Command -Type Function

## Modules (the source of every command)
Get-Module