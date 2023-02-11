[![Packaging status](https://repology.org/badge/tiny-repos/dcfldd.svg)](https://repology.org/project/dcfldd/versions)

# dcfldd

#### dcfldd - enhanced version of dd for forensics and security

## Help this project ##

dcfldd needs your help. **If you are a programmer** and if you want to help a
nice project, this is your opportunity.

dcfldd was imported from some tarballs (the original homepage[1] and
developers are inactive). After this, all patches found in Debian project and
other places for this program were applied. All initial work was registered in
ChangeLog file (version 1.5 and later releases). 

If you are interested to help dcfldd, read the [CONTRIBUTING.md](CONTRIBUTING.md) file.

[1]: https://sourceforge.net/projects/dcfldd

## What is dcfldd? ##

dcfldd is a modified version of GNU dd. The major features added are:

  - Hashing on-the-fly: dcfldd can hash the input data as it is being
    transferred, helping to ensure data integrity.
  - Status output: dcfldd can update the user of its progress in terms of the
    amount of data transferred and how much longer operation will take.
  - Flexible disk wipes: dcfldd can be used to wipe disks quickly and with a
    known pattern if desired.
  - Image/wipe verify: dcfldd can verify that a target drive is a bit-for-bit
    match of the specified input file or pattern.
  - Multiple outputs: dcfldd can output to multiple files or disks at the same
    time.
  - Split output: dcfldd can split output to multiple files with more
    configurability than the split command.
  - Piped output and logs: dcfldd can send all its log data and output to
    commands as well as files natively.

dcfldd was originally created by Nicholas Harbour from the DoD Computer
Forensics Laboratory (DCFL). Nick Harbour still maintaining the package,
although he was no longer affiliated with the DCFL.

Nowadays, dcfldd is maintained by volunteers.

## Build and Install ##

To build and install, run the following commands:

    $ ./autogen.sh
    $ ./configure
    $ make
    # make install

To return to original source code you can use '$ make distclean' command.

On Debian systems you can use '# apt install dcfldd'.

There is a bash completion file inside doc/ directory in source code.

## Author ##

dcfldd was originally developed by Nicholas Harbour under GPL-2+ license.

Currently, the source code and newer versions are available at
https://github.com/resurrecting-open-source-projects/dcfldd

See AUTHORS file for more information.
