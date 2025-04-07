---
title: "Audio controlled Shelly devices"
subtitle: "I can see you're talking to me in riddles. Do what you like, you go where the wind blows."
date: 2022-06-13T17:32:50+03:00
tags: ["voks", "shelley", "linux", "opens source", "accesibility"]
type: post
---


The idea came from [Tina Müller](https://github.com/perlpunk) who was giving and awesome demo of the Vosk library. I quickly checked out the [Alphacephei](https://alphacephei.com/vosk/) pages.

I fundamentally like when a cool library has Python APIs.

Vosk is an offline open source speech recognition toolkit. It enables speech recognition for lots of languages. The vosk models are small (50 Mb) but still provide continuous large vocabulary transcription, zero-latency response with streaming API.

Installing vosk library on my openSUSE Tumbleweed goes like 
```
pip3 install vosk
```

I usually start with checking out the examples provided with the API implementation. To get the python samples I needed to clone the vosk-api:

```
git clone https://github.com/alphacep/vosk-api
```

My goal was to control the Shelly lights in my home with voice control.


### Some words about API design

Now, when it comes to Shelly Cloud API it becomes obviously visible what is a different a poorly done API and a well done API.

A good API consist of the following important parts:

- Documentation
- Example code
- Open source implementation
- Robust tests

While the Vosk API commendably fulfills my requirements  the Shelly API has only a pretty poor [documentation](https://shelly.cloud/documents/developers/shelly_cloud_api_access.pdf)

I am very far from being impressed with the Shelly Cloud API. For this excercise I wanted to try out the cloud API to see how it works compare to the MQTT (Message Queue Telemetry Transport) what I played with [earlier](https://bzoltan1.github.io/playing-with-shelly/). I must say that already at half way I have decided that the next will be to migrate to [Nymea](https://nymea.io/) as I have heard only positive words about it.

True the simplicity of Shelly Cloud API is appealing. But for example their limitation that it can serve only one request per second is really annoying. This limitation means that if I request the status of a Shelly device then I need to sleep() for at least a full second before I can fire up the command to change that status. So a simple status switching call (turn it off if it was on or turn it on if it was off) is a 1.5-2 seconds job. And that is not acceptable. I have opened a ticket at Shelly's customer service but they told me that such as life. 

### Implementation

I have used the simplest examples as design patterns to make a super simple application: [https://github.com/bzoltan1/vosk-shelly)](https://github.com/bzoltan1/vosk-shelly)

The Python code is self explaining in my opinion, but basically all it takes is 

```
import vosk 
```

create a qeueue  

```
q = queue.Queue() 
```

fire up the vosk model

```
model = vosk.Model(lang="en-us") 
```

Listen to the audio device with 

```
sd.RawInputStream(samplerate=44100, blocksize=8000, device=None, dtype='int16', channels=1, callback=callback): 
```

capture the recognized text

```
rec = vosk.KaldiRecognizer(model, 44100) 
```

And launch a while loop

and process the result what
```
rec.AcceptWaveform(data) 
```

and

```
rec.Result() 
```

gives.

After that it is up to the program's logic to send a http request with the POST command like 
`https://[instance].cloud/device/light/control?id=[]&auth_key=[]&turn=[on|off]` 

### Lessons learned

First of all, it is super cool that speech recognition is available in the open source scene and I am happy that Tina draw my attention to that. It is surprisingly easy to develop small and smart applications.  Turning on and off smart lights is just one thing. But with a  low budget Raspberry Pi and with a good speech synthesis software one can ask from bed about the weather forecast, number of unread emails or the content of instant messages. 

Also with a privacy safe voice controlling system we can build cool accessibility and emergency applications.

### The proof

A friend of mine was laughing when I was giving them a demo that the video does not show me switching on and off the physical light switch :)
I guess you need to trust me with this.

{{< rawhtml >}}

<video width=100% controls>
    <source src="/vosk-shelley.mp4" type="video/mp4">
    Your browser does not support the video tag.
</video>

{{< /rawhtml >}}

