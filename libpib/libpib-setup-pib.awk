BEGIN {
	dir="/sys/bus/pci/drivers/pib"
	if (system("[ -d "dir" ]") != 0)
		exit 1
}
/^[[:xdigit:]]+:[[:xdigit:]]+:[[:xdigit:]]+\.[[:xdigit:]]([[:blank:]](ib|eth|auto))+/ {
	device=$1
	port1=$2
	port2=$3
	if (system("[ -d "dir"/"device" ]") != 0)
		next
	if (system("[ -f "dir"/"device"/port_trigger ]") == 0)
		print "all" > dir"/"device"/port_trigger"
	if (system("[ -f "dir"/"device"/mlx4_port2 ]") == 0)
		print port2 > dir"/"device"/mlx4_port2"
	if (system("[ -f "dir"/"device"/mlx4_port1 ]") == 0)
		print port1 > dir"/"device"/mlx4_port1"
}
