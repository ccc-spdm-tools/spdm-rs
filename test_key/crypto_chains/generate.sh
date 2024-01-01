
openssl genrsa -out ca.key 2048
openssl req -extensions v3_ca -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=intel test RSA CA"
openssl x509 -in ca.crt -out ca.crt.der -outform DER

openssl req -nodes -newkey rsa:2048 -keyout inter0.key -out inter0.req -sha256 -batch -subj "/CN=intel test RSA intermediate cert0"
openssl x509 -req -in inter0.req -out inter0.crt -CA ca.crt -CAkey ca.key -sha256 -days 3650 -set_serial 2 -extfile ./openssl.cnf -extensions v3_inter
openssl x509 -in inter0.crt -out inter0.crt.der -outform DER

openssl req -nodes -newkey rsa:2048 -keyout inter1.key -out inter1.req -sha256 -batch -subj "/CN=intel test RSA intermediate cert1"
openssl x509 -req -in inter1.req -out inter1.crt -CA inter0.crt -CAkey inter0.key -sha256 -days 3650 -set_serial 3 -extfile ./openssl.cnf -extensions v3_inter1
openssl x509 -in inter1.crt -out inter1.crt.der -outform DER

openssl req -nodes -newkey rsa:2048 -keyout  end.key -out end.req -sha256 -batch -subj "/CN=intel test RSA end"
openssl x509 -req -in end.req -out end.crt -CA inter1.crt -CAkey inter1.key -sha256 -days 3650 -set_serial 4 -extfile ./openssl.cnf -extensions v3_end
openssl x509 -in end.crt -out end.crt.der -outform DER

cat ca.crt.der inter0.crt.der inter1.crt.der end.crt.der > bundle_cert.der

openssl req -nodes -newkey rsa:2048 -keyout end_two_level.key -out end_two_level.req -sha256 -batch -subj "/CN=intel test RSA  two level cert"
openssl x509 -req -in end_two_level.req -out end_two_level.crt -CA ca.crt -CAkey ca.key -sha256 -days 3650 -set_serial 2 -extfile ./openssl.cnf -extensions v3_end
openssl x509 -in end_two_level.crt -out end_two_level.crt.der -outform DER
cat ca.crt.der end_two_level.crt.der > bundle_two_level_cert.der 

openssl req -x509 -sha256 -days 356 -nodes -newkey rsa:2048 -subj "/CN=intel test RSA" -keyout ca_selfsigned.key -out ca_selfsigned.crt -config openssl.cnf -extensions v3_selfsigned
openssl x509 -in ca_selfsigned.crt -out ca_selfsigned.crt.der -outform DER
