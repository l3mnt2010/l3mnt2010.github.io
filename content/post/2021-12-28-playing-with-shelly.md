---
title: "Playing with Shelly"
subtitle: "Finally I can turn on the lights from CLI"
date: 2021-12-28T10:35:50+03:00
tags: ["mqtt", "shelly", "iot", "mosquitto","opensuse"]
type: post
---
  
For xmass I got few Shelly lamps to play with. Shelly lamps are simple IoT devices. Super easy to install, configure and use. The Youtube is full with instructions on what can be done with these smart lamps.
Naturally my main motivation was to figure out how to hack these devices and how ready my openSUSE servers are with tools and services (spoiler: they are ready)

### Look daddy no cloud

Needless to say that like most smart home automation devices the Shelly lamps can be operated via the Shelly cloud. I may cover that area in the next post. But now I am interested in what can be done without the cloud. After all, one big selling point of the Shelly devices is that they are fully operable and functional even without Internet connection just on a WiFi LAN. It means that if I am concerned about the security of my home infrastructure I have an option not to expose my smart devices.

### Here is what I have done

So I plugged in the lamp in my study, configured it to connect to my WiFi network and enabled the MQTT.

MQTT (Message Queue Telemetry Transport), is a lightweight communication protocol based on the publisher/subscriber concep and widely used in the Internet of Things. MQTT is often used for receiving parameters measured by sensors and to send simple commands to IoT devices like my lamp.

In order to use MQTT protocol I need a broker server in my network.

The mosquitto package is available in openSUSE and it is a widely used message broker that implements the MQ Telemetry Transport protocol versions 3.1 and 3.1.1. 

```bash
# zypper install mosquitto
```

On my openSUSE Tumbleweed it installs  libcjson1 libmosquitto1 libwebsockets12 mosquitto.  I enable and start the mosquitto server:

The mosquitto server can be configured to require client authentication (username and password). The credentials are transmitted in clear text, so it is not very secure without proper transport encryption. However using username and password authentication does provide some level of security and as I am playing on my reasonable well guarded LAN I am fine with this level of security.
First I created password file for the server:

```bash
# mosquitto_passwd -c /etc/mosquitto/passwd shelly
```

Where shelly is the username. This command will ask for password and create the /etc/mosquitto/passwd file. Naturally the mosquitto server need to be configured to use authentication based on the content of this file. I added few extra options to the  /etc/mosquito/mosquitto.conf :

```bash
[...]
listener 1883
allow_anonymous true
per_listener_settings true
password_file /etc/mosquitto/passwd
```

Finally I starter and enabled the service:

```bash
# systemctl start mosquitto
# systemctl enable mosquitto
```

I also need to install the client applications. Note that it does not need to be used on the mqtt server. I use it on my laptop.

```bash
# zypper install  mosquitto-clients
```

Now I need to discover my MQTT enabled Shelly device(s) on my LAN. I love single purpose oneliners:

```
for IP in $(arp-scan 192.168.1.0/24 --plain|awk '{print $1}'); do curl -s http://$IP/status |python -m json.tool 2>&1|grep -v No|egrep "\"ip|\"mqtt\"" -A1|egrep -v "\-\-|rssi"; done
```

Once I found the IP address of my Shelly lamp I can ask it for the settings details:

```
curl -s http://192.168.1.122/settings|python -m json.tool
```
It tells me for example that the mqtt id of my lamp is ShellyBulbDuo-E8DB84A9E51B.

Now I have all the services, tools and information to adjust my Shelly lamp from command line.

First I need to set few variables

```bash
$ export MQTT_SERVER="192.168.1.123"
$ export MQTT_PORT=1883
$ export MQTT_USER="shelly"
$ export MQTT_PW="shelly"
$ export DEVICE_ID="ShellyBulbDuo-E8DB84A9E51B"
```

```
mosquitto_pub -h ${MQTT_SERVER} -p ${MQTT_PORT} -u ${MQTT_USER} -P ${MQTT_PW} -t shellies/${DEVICE_ID}/light/0/set  -m '{"brightness":33, "white": 0, "temp": 2700, "turn": "on", "transition": 2000 }'
```

One handy command I have learned about is to subscribe to all announcements and figure out more about the mqtt devices, topics and properties.

```
mosquitto_sub -h ${MQTT_SERVER} -p ${MQTT_PORT} -u ${MQTT_USER} -P ${MQTT_PW} -t '#' -v
```


### Summary

All in all it was a really easy and fast kick start. Playing with mqtt is fun and after installing few extra packages I could operate my Shelly lamp from my openSUSE. I could set up cron jobs to turn off or on the lamp. I could trigger blinking when something happens on my server. I set up bash aliases to change the ambiance of my study room.
And what is really cool that I could do it without exposing my smart device to a 3rd party cloud provided and without opening up security holes on my network.

