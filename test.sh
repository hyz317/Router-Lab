sudo ip netns exec PC2 iperf3 -s
sudo ip netns exec PC1 iperf3 -c 192.168.5.1
sudo ip netns exec PC1 iperf3 -c 192.168.5.1 -u -l 16 -t 5 -b 1G