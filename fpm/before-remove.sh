sed -i '/^###BEGIN-ZEYPLE$/,/^###END-ZEYPLE$/d' /etc/postfix/master.cf
sed -i '/^content_filter = zeyple$/d' /etc/postfix/main.cf
postfix reload
