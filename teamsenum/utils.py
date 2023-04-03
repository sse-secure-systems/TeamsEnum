#!/usr/bin/python3

import sys
import os
from colorama import Fore, Style
import errno

def p_err(msg, exit=False, exitcode=1, end="\n"):
   """
   Prints a string, highlighted in red.

   Args:
       msg (str): The message to be printed.
       exit (boolean): If True, exits after printing the message
       exitcode (int): If exit is True, exit program using this exit code
       end (str): Line terminator after printing. Defaults to newline

   Returns:
       None
   """
   print(Fore.RED + "[-] ", end='')
   p_normal(msg, exit, exitcode, end)

def p_warn(msg, exit=False, exitcode=1, end="\n"):
   """
   Prints a string, highlighted in yellow.

   Args:
       msg (str): The message to be printed.
       exit (boolean): If True, exits after printing the message
       exitcode (int): If exit is True, exit program using this exit code
       end (str): Line terminator after printing. Defaults to newline

   Returns:
       None
   """
   print(Fore.YELLOW + "[-] ", end='')
   p_normal(msg, exit, exitcode, end)

def p_success(msg, exit=False, exitcode=0, end="\n"):
   """
   Prints a string, highlighted in green.

   Args:
       msg (str): The message to be printed.
       exit (boolean): If True, exits after printing the message
       exitcode (int): If exit is True, exit program using this exit code
       end (str): Line terminator after printing. Defaults to newline

   Returns:
       None
   """
   print(Fore.GREEN + "[+] ", end='')
   p_normal(msg, exit, exitcode, end)

def p_info(msg, exit=False, exitcode=0, end="\n"):
   """
   Prints a string, highlighted in cyan.

   Args:
       msg (str): The message to be printed.
       exit (boolean): If True, exits after printing the message
       exitcode (int): If exit is True, exit program using this exit code
       end (str): Line terminator after printing. Defaults to newline

   Returns:
       None
   """
   print(Fore.CYAN + "[~] ", end='')
   p_normal(msg, exit, exitcode, end)

def p_normal(msg, exit=False, exitcode=0, end="\n"):
   """
   Prints a string.

   Args:
       msg (str): The message to be printed.
       exit (boolean): If True, exits after printing the message
       exitcode (int): If exit is True, exit program using this exit code
       end (str): Line terminator after printing. Defaults to newline

   Returns:
       None
   """
   print(msg, end='')
   print(Style.RESET_ALL, end=end)
   if exit:
      sys.exit(exitcode)

def p_file(msg, fd=None):
   """
   Writes a message to the provided file descriptor

   Args:
       msg (str): The message to be written into a file.
       fd (_io.TextIOWrapper): File descriptor used for file write

   Returns:
       None
   """
   if fd is None:
      return
   fd.write(msg)
   fd.write("\n")
   fd.flush()

def open_file(filename):
   """
   Prints a string.

   Args:
       filename (str): Name of the file that is used for logging the results

   Returns:
       File descriptor (_io.TextIOWrapper): File descriptor that is later used for write operations
   """
   try:
      os.stat(filename)
      overwrite = ""
      while overwrite not in ["y","n"]:
         p_warn("The output file already exists. Overwrite? (y/n): ", end='')
         overwrite = input()
      if overwrite == "n":
         p_warn("Output file will not be overwritten. Please choose another file", True, 1)

   except FileNotFoundError as err:
      pass

   try:
      fd = open(filename, 'w')
   except IOError as err:
      if err.errno == errno.EACCES:
         p_warn("No permissions to write output file", True, 1)
      elif err.errno == errno.EISDIR:
         p_warn("Output file is a directory", True, 1)

   return fd
