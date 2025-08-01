# pwstore

simple password mananger for unix scripts

works on Solaris, AIX and Linux
tested on Solaris and Linux

## compile on Linux
```
gcc -O3 -D_FORTIFY_SOURCE=2 -fstack-protector-all \
    --param=ssp-buffer-size=1 pwstore.c -D LINUX -o pwstore
```

## usage
```
/opt/pwstore/bin/pwstore list           # list all <keys> readable by current user on current system
/opt/pwstore/bin/pwstore add key1 key2  # add password for <key1> <key2> for current user on current system
/opt/pwstore/bin/pwstore read key1 key2 # output password for <key1> <key2> for current user on current system
```

## install (via sudo)

```
sudo mkdir -p /opt/pwstore
sudo chmod a+rx /opt/pwstore
sudo chmod u+rwx /opt/pwstore
sudo chmod og-w /opt/pwstore

sudo mkdir -p /opt/pwstore/bin
sudo chmod u+rwx /opt/pwstore/bin
sudo chmod og-rw /opt/pwstore/bin
sudo chmod og+x /opt/pwstore/bin

sudo mkdir -p /opt/pwstore/conf
sudo chmod u+rwx /opt/pwstore/conf
sudo chmod og-rwx /opt/pwstore/conf

sudo cp -av pwstore /opt/pwstore/bin/pwstore
sudo chown root:root /opt/pwstore/bin/pwstore
sudo chmod og-rw /opt/pwstore/bin/pwstore
sudo chmod og+x /opt/pwstore/bin/pwstore
sudo chmod u+rwx /opt/pwstore/bin/pwstore
sudo chmod u+s /opt/pwstore/bin/pwstore
```

<br>
Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.
<br>
No part of this work may be used or reproduced in any manner for the purpose of training artificial intelligence technologies or systems.

