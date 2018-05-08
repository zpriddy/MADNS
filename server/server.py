import requests
from flask import Flask, jsonify

googleDNSUrl = 'https://dns.google.com/resolve?name=%s&type=%s'

blackholeList = ['cnn.com', 'www.cnn.com']
bhAnswer = {
  'AD':      False,
  'Answer':  [{
                'TTL':  299,
                'data': '127.0.0.1',
                'name': 'a.com.',
                'type': 1
              }],
  'CD':      False,
  'Comment': 'Blackholed',
  'RA':      True,
  'RD':      True,
  'Status':  0,
  'TC':      False
}

app = Flask(__name__)


@app.route('/')
def hello_world():
  return 'Hello World!'


@app.route('/dns/<domain>/<requestType>')
def dns_lookup(domain=None, requestType=None):
  if domain is None or requestType is None:
    return '0.0.0.0'
  if domain == 'dns.google.com':
    return {
      "Question": [
        {
          "name": "dns.google.com.",
          "type": 1
        }
      ],
      "Answer":   [
        {
          "name": "dns.google.com.",
          "type": 1,
          "TTL":  299,
          "data": "216.58.194.206"
        }
      ],
      "Comment":  "Response from 216.239.36.10."
    }
  if domain in blackholeList:
    print('blackhole')
    a = bhAnswer
    a['Answer'][0]['name'] = domain
    return jsonify(a)
  url = googleDNSUrl % (domain, requestType)
  answer = requests.get(url)
  return jsonify(answer.json())


if __name__ == '__main__':
  app.run()
