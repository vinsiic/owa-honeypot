# owa-honeypot
Original code was forked from [Willem Mouton aka joda32](https://github.com/joda32/owa-honeypot).

This is a basic Python3 Flask based Outlook Web Honey pot, but given some minor adjustments and added dependency on newer module versions from original code.

![](docs/OWA_honeypot_1.png)

## why?
There is always some pesky people who try to do some _bad_ authorization things to corp OWA.

## requirements
python3 + flask + gunicorn (fastes way to replace server header tag)

## how to install

```sh
git clone https://github.com/joda32/owa-honeypot.git
cd owa-honeypot
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

# to customize, copy .env.demo to .env and make necessary modifications
# cp .env.demo .env

gunicorn -c gunicorn.conf.py owa_pot:app
```

## screens

![](docs/OWA_honeypot_2.png)
![](docs/OWA_honeypot_3.png)
