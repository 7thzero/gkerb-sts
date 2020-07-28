#!/bin/bash
#
# Deploys gkerb-sts locally
#
# Be sure to add a bash alias if you want it to replace 'kerb-sts'!
#
# Alias example:
#   $ alias kerb-sts='gkerb-sts -IdentityIrpPath=<identity_irp_url_here>'

rm -rf /home/$USER/go/bin/gkerb-sts
cp -n gkerb-sts /home/$USER/go/bin/gkerb-sts

rm -rf /home/$USER/.local/bin/gkerb-sts
cp -n gkerb-sts /home/$USER/.local/bin/gkerb-sts