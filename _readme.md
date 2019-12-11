---
imagine.shebang.im_out: stderr
imagine.shebang.im_log: 4
...

# JABS - Just automating boring stuff

Small collection of utilities for enriching/filtering log-files

- dfm - dataframe manipulation
- namedrop - drop names/info found by ipv4 adresses in ip-lookup tables (csv)
- ls.ifaces - get list of interfaces with properties from cisco config files
- heatmap - turn specific syslogs into a heatmap for a bunch of interfaces

Run

```
# If pytest not installed yet:
$ sudo pip3 install -U pytest

# Then move to test-subdir of jabs project and run pytest:
cd ~/dev/jabs/test
pytest
```

# Usage

## dfm
```shebang
#!/bin/bash

dfm help:dfm
```

## dfm example

Show traffic from some systems:

```{.shebang im_out=img,fcb}
#!/bin/bash

SUBNETS=example/subnets.csv

LOGS=example/logs.csv
DOTF=${LOGS%.csv}.dot
VPNF=${LOGS%.csv}+vpns.csv
IMGF=$1

# read $LOG -> write enriched logs to $VPNF and dotify to $DOTF
# then turn dot-file into image

dfm r:$LOGS \
    src_vpn=ipl:$SUBNETS,src,vpn \
    dst_vpn=ipl:$SUBNETS,dst,vpn \
    src,dst,srv,count,src_vpn,dst_vpn=keep: \
    count=sum: \
    w:$VPNF \
    $DOTF,VPN-traffic=dotify:src_vpn^src,dst_vpn^dst,srv \
    -v -d

dot -Tpng $DOTF -o $IMGF
```

where `example/logs.csv` contains:

```shebang
#!/bin/bash
cat example/logs.csv
```

which is enriched, using `example/subnets.csv`  with vpn information:

```shebang
#!/bin/bash
cat example/logs+vpns.csv
```

which in turn, is converted into a graphviz file containing:

```shebang
#!/bin/bash
cat example/logs.dot
```

which is converted to an image by the `dot` command.  Although cute and perhaps
sometimes useful, it gets pretty messy, pretty fast if the number of hosts or
number of sessions gets large.


# Documentation

## dfm (sub)commands

`dfm` allows commandline manipulation of a log file read into a pandas
dataframe.  Add, delete, keep columns or filter rows based on a regex.  Rows
can be filtered using a regex on columns or an ip filter.

```shebang
#!/bin/bash

dfm help:
```

# ToDo:

    x re-install all requirements
    x refresh requirements via pip3 freeze > requirements.txt
    o add howto use ilf's filtering
    o add script using ilf that creates graphiz images from ip session logs
    o add networkx to create interactive graphs (if possible ?)
    o dfm
      o rework dfm so it is easier to use - cmd parsing using ply ?
      o add narrow/expand cmds to work on subsets of the df
        auto-expand after 1 cmd or use explicit expand cmd
        - sometimes you'll want to set a column value based on a selection?
