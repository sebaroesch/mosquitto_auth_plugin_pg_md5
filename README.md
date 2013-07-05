mosquitto_auth_plugin_pg_md5
============================

Auth plugin for Mosquitto MQTT broker which checks password against MD5 hash in Postrgres DB

----- WARNING -----
The contained code is by no means ready for a productive system. 
Actually it is a result of a ersonal experiment and my first C-code at all, so take it with a (enormous) grain of salt.
----- WARNING -----

The goal of the plugin is to check the user credentials against the MD5 hash of the password, which is stored in a Postgres database. 
Additionally, the plugin distinguishs between a connecting "server" and clients, where the clients are limited to read from the topic 
"/<username>/warning" and to write to the topic "/<username>/status". The server can read from "/#/status" (# as wildcard). 
Currently the server can write to all topics, this needs to be limited to "/#/warning" in a future update.

The code is based on / inspired by:
https://bitbucket.org/oojah/mosquitto/src/551faaef7bce25d9a347f28e3dbea57445593e90/examples/mysql_log/mysql_log.c
https://github.com/sskaje/mosquitto_auth_plugin_md5
