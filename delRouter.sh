sudo ip netns exec R1 ip route del 10.0.2.0/24
sudo ip netns exec R1 ip route del 10.0.3.0/24
sudo ip netns exec R1 ip route del 192.168.4.0/24
sudo ip netns exec R1 ip route del 192.168.5.0/24

sudo ip netns exec R3 ip route del 10.0.2.0/24
sudo ip netns exec R3 ip route del 10.0.3.0/24
sudo ip netns exec R3 ip route del 192.168.1.0/24
sudo ip netns exec R3 ip route del 192.168.3.0/24
