# pwstore

simple password mananger for unix scripts

works on Solaris, AIX and Linux
tested on Solaris and Linux

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

