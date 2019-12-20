sudo ip netns add PC1
sudo ip netns add R1
sudo ip netns add R2
sudo ip netns add R3
sudo ip netns add PC2

sudo ip link add pc1r1 type veth peer name r1pc1
sudo ip link set pc1r1 netns PC1 # 将 veth 一侧加入到一个 namespace 中
sudo ip link set r1pc1 netns R1 # 配置 veth 另一侧
sudo ip netns exec PC1 ip link set pc1r1 up
sudo ip netns exec PC1 ip addr add 192.168.1.2/24 dev pc1r1 # 给 veth 一侧配上 ip 地址
sudo ip netns exec R1 ip link set r1pc1 up
sudo ip netns exec R1 ip addr add 192.168.1.1/24 dev r1pc1
echo "finish pc1r1"

sudo ip link add r1r2 type veth peer name r2r1
sudo ip link set r1r2 netns R1 # 将 veth 一侧加入到一个 namespace 中
sudo ip link set r2r1 netns R2 # 配置 veth 另一侧
sudo ip netns exec R1 ip link set r1r2 up
sudo ip netns exec R1 ip addr add 192.168.3.1/24 dev r1r2 # 给 veth 一侧配上 ip 地址
sudo ip netns exec R2 ip link set r2r1 up
# sudo ip netns exec R2 ip addr add 192.168.3.2/24 dev r2r1
echo "finish r1r2"

sudo ip link add r2r3 type veth peer name r3r2
sudo ip link set r2r3 netns R2 # 将 veth 一侧加入到一个 namespace 中
sudo ip link set r3r2 netns R3 # 配置 veth 另一侧
sudo ip netns exec R2 ip link set r2r3 up
# sudo ip netns exec R2 ip addr add 192.168.4.1/24 dev r2r3 # 给 veth 一侧配上 ip 地址
sudo ip netns exec R3 ip link set r3r2 up
sudo ip netns exec R3 ip addr add 192.168.4.2/24 dev r3r2
echo "finish r2r3"

sudo ip link add r3pc2 type veth peer name pc2r3
sudo ip link set r3pc2 netns R3 # 将 veth 一侧加入到一个 namespace 中
sudo ip link set pc2r3 netns PC2 # 配置 veth 另一侧
sudo ip netns exec R3 ip link set r3pc2 up
sudo ip netns exec R3 ip addr add 192.168.5.2/24 dev r3pc2 # 给 veth 一侧配上 ip 地址
sudo ip netns exec PC2 ip link set pc2r3 up
sudo ip netns exec PC2 ip addr add 192.168.5.1/24 dev pc2r3
echo "finish r3pc2"

sudo ip netns exec PC1 ip route add default via 192.168.1.1 dev pc1r1
sudo ip netns exec PC2 ip route add default via 192.168.5.2 dev pc2r3

sudo ip netns exec R1 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec R2 sysctl -w net.ipv4.ip_forward=0
sudo ip netns exec R3 sysctl -w net.ipv4.ip_forward=1

sudo ip netns exec PC1 ethtool -K pc1r1 tx off
sudo ip netns exec PC2 ethtool -K pc2r3 tx off
