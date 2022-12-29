#!/bin/bash
set -x

# cleanup
rm -rf nginx/
rm -rf openssl/

# install pre-requisites
sudo apt install -y libssl-dev libc-dev linux-headers-$(uname -r) libpcre3 libpcre3-dev

# configure openSSL
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout OpenSSL_1_1_1f
git switch -c feature/bounds-check
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
git am ../openssl-psychic.patch
./config no-ssl2 no-ssl3 no-comp no-idea no-dtls no-dtls1 no-psk no-srp no-weak-ssl-ciphers --openssldir=/usr/local/ssl --prefix=/usr/local/ssl
cd ..

# configure and compile Nginx
git clone https://github.com/nginx/nginx.git
cd nginx
./auto/configure \
    --build=psychic \
    --with-http_ssl_module \
    --without-http_gzip_module \
    --with-pcre \
    --sbin-path=/usr/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --with-openssl=/home/vagrant/openssl \
    --modules-path=/usr/lib/nginx/modules \
    --pid-path=/run/nginx.pid \
    --prefix=/usr/lib/nginx
make
sudo cp ./objs/nginx /usr/sbin/nginx
for file in 50-mod-http-image-filter.conf 50-mod-http-xslt-filter.conf 50-mod-mail.conf 50-mod-stream.conf
do
    sudo mv /etc/nginx/modules-enabled/${file} /etc/nginx/modules-enabled/${file}.BAK
done
cd ..

# restart nginx
which nginx
ll $(which nginx)
nginx -version
sudo systemctl restart nginx
sudo systemctl status nginx

# cleanup (leaving some traces)
rm openssl-psychic.patch
rm -rf nginx/.git/
rm -rf openssl/.git/

