
my @a = qw/1 7 13 5 11 4 10 3 9 2 8/;

while(1){
	foreach(@a){
		$b = `airport en0 sniff $_ & 1>/dev/null 2>/dev/null`;
		sleep 1
	}
}
