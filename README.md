# ideviceunback - Decode manifest and copy files in to human readable form from idevicebackup2 output

Since iOS 9.3.2 the idevicebackup2 tool has not been able to perform the 'unback' function as Apple removed the facility.

ideviceunback replaces this functionality

Currently in ALPHA development phase.


### Installation

1. Clone the project

    $ git clone https://github.com/inflex/ideviceunback.git

2. Build it

    $ make

3. Run it!

	$ ./ideviceunback -h

	...or...

	$ ./ideviceunback -v -i path/to/backup -o output/path

