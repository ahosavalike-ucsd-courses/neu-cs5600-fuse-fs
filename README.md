Lab 3 repos

Your lab 3 repository is ready, with the following files:

• Makefile
• fs5600.h  (structure definitions)
• misc.c, hw3fuse.c (don’t modify these)
• homework.c (skeleton code for your solution)
• disk1.img (sample disk image)
You can compile with make, and to run the FUSE file system executable you need to specify a disk image file and a directory, e.g.:

```
make
mkdir tmp
./lab3-fuse -s -d -image disk1.img tmp
```

Now you can go into another window and try to examine the tmp directory. If you haven’t added any code, you’ll see something like this:

```
hw3$ ls -l x
ls: cannot access 'x': Function not implemented
```

NOTE: to shut down you HAVE to run the following command: `fusermount -u <directory>`
Even if you killed the program with ^C, or it crashed, or whatever. If you get an error like “fuse: failed to access mountpoint”, it’s because you didn’t use fusermount -u to clean up from the last run.
