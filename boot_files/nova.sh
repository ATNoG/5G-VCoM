#!/bin/bash
AUTOR="Flavio Meneses @ University of Aveiro, 2016"
USAGE="Usage: `basename -- $0` -h | help"
FILE="/home/ubuntu/vmn_pktin.sh"
IP=""

if [[ "$1" == "-h" ]] 
then
  echo ""
  echo "$USAGE"
  echo "AUTOR: $AUTOR"
  echo ""
  echo "[-h ]    help"
  echo "[-ip  <MN ip address>]  IP of the MN"
  echo ""
  return

else
  if [ "$#" -ne 2 ]
  then
  	echo "$USAGE"
	return
  else
    if [[ "$1" == "-ip" ]] 
    then
        IP="$2"
    else
        echo "Invalid argument [$1]"
        echo "$USAGE"
        return
    fi
  fi
fi

echo '#!/bin/bash' > $FILE
echo 'bash /home/ubuntu/vmnboot.sh -ip '$IP'' >> $FILE

IMAGE_ID="TODO"
KEY_NAME=""
FLAVOR_ID="TODO"
ZONE="TODO"
NET_ID=""
SGROUPS="all"
USER_DATA_FILE=$FILE
INSTANCE_NAME="vmn"
CREDS_FILE="prjct-openrc.sh"

source $CREDS_FILE

nova boot --image $IMAGE_ID --key-name $KEY_NAME --flavor $FLAVOR_ID --availability-zone $ZONE --nic net-id=$NET_ID --security-groups $SGROUPS --user-data $USER_DATA_FILE $INSTANCE_NAME
