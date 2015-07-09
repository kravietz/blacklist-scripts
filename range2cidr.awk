# AWK script to convert iblocklist.com ranges into CIDR format
# usable with ipset

# based on scripts posted at 
# http://www.unix.com/shell-programming-and-scripting/233825-convert-ip-ranges-cidr-netblocks.html

function bit_or(a, b, r, i, c) {
    for (r=i=0;i<32;i++) {
        c = 2 ^ i
        if ((int(a/c) % 2) || (int(b/c) % 2)) r += c
    }
    return r
}
function bit_lshift(var, x) {
  while(x--) var*=2;
  return var;
}
function bit_rshift(var, x) {
  while(x--) var=int(var/2);
  return var;
}
function range2cidr(ipStart, ipEnd,  bits, mask, newip) {
    bits = 1
    mask = 1
    while (bits < 32) {
        newip = bit_or(ipStart, mask)
        if ((newip>ipEnd) || ((bit_lshift(bit_rshift(ipStart,bits),bits)) != ipStart)) {
           bits--
           mask = bit_rshift(mask,1)
           break
        }
        bits++
        mask = bit_lshift(mask,1)+1
    }
    newip = bit_or(ipStart, mask)
    bits = 32 - bits
    result = dec2ip(ipStart) "/" bits
    if (newip < ipEnd) result = result "\n" range2cidr(newip + 1, ipEnd)
    return result
}
function ip2dec(ip,   slice) {
    split(ip, slice, ".")
    return (slice[1] * 2^24) + (slice[2] * 2^16) + (slice[3] * 2^8) + slice[4]
}
function dec2ip(dec,    ip, quad) {
	for (i=3; i>=1; i--) {
		quad = 256^i
		ip = ip int(dec/quad) "."
		dec = dec%quad
	}
	return ip dec
}

# example iblocklist.com format
# TOT Public Company/Irdeto:1.0.128.0-1.0.255.255
BEGIN { FS = ":"; }

$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
    n = split($2, array, "-");
    if (n == 2) {
        ip1 = array[1];
        ip2 = array[2];
        if (ip1 == ip2) {
            # some records are just single IPs listed as range
            print ip1;
        } else {
            # and some are really ranges
            print range2cidr(ip2dec(ip1), ip2dec(ip2));
        }
    }
}
