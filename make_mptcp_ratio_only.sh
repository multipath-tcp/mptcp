echo "Unloading mptcp_ratio..."
rmmod mptcp_ratio
echo "Buiding mptcp submodules..."
make -C . M=net/mptcp
echo "Copying mptcp_ratio.ko..."
cp net/mptcp/mptcp_ratio.ko /lib/modules/4.19.224/kernel/net/mptcp/mptcp_ratio.ko
echo "Reloading mptcp_ratio..."
modprobe mptcp_ratio
echo "Done!"
