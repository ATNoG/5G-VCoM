
docker tag registry.local:5005/firewall registry-host:5000
docker tag registry.local:5005/dhcp-server registry-host:5000
docker push registry.local:5005/firewall
docker push registry.local:5005/dhcp-server
