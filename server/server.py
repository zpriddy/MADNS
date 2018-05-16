import requests
import tldextract
from flask import Flask, jsonify, render_template
from flask_mongoengine import MongoEngine
from flask_security import MongoEngineUserDatastore, RoleMixin, Security, UserMixin, login_required
from pymongo import MongoClient

googleDNSUrl = 'https://dns.google.com/resolve?name=%s&type=%s'

sinkhole_list = ['zpriddy.com']
bhAnswer = {
  'AD':      False,
  'Answer':  [{
    'TTL':  299,
    'data': '127.0.0.1',
    'name': 'a.com.',
    'type': 1
  }],
  'CD':      False,
  'Comment': 'Shinkholed',
  'RA':      True,
  'RD':      True,
  'Status':  0,
  'TC':      False
}

# Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'

# MongoDB Config
app.config['MONGODB_DB'] = 'mydatabase'
app.config['MONGODB_HOST'] = 'localhost'
app.config['MONGODB_PORT'] = 27017
app.config['SECURITY_PASSWORD_SALT'] = 'This'

# Create database connection object
db = MongoEngine(app)


class Role(db.Document, RoleMixin):
  name = db.StringField(max_length=80, unique=True)
  description = db.StringField(max_length=255)


class User(db.Document, UserMixin):
  email = db.StringField(max_length=255)
  password = db.StringField(max_length=255)
  active = db.BooleanField(default=True)
  confirmed_at = db.DateTimeField()
  roles = db.ListField(db.ReferenceField(Role), default=[])


# Setup Flask-Security
user_datastore = MongoEngineUserDatastore(db, User, Role)
security = Security(app, user_datastore)

client = MongoClient()
db = client.madns
sinkhole_datastore = db.sinkhole


# Create a user to test with
@app.before_first_request
def create_user():
  user_datastore.create_user(email='test@zpriddy.com', password='password')


# Views
@app.route('/')
@login_required
def home():
  return 'logged in'


@app.route('/manage_sinkhole')
@login_required
def manage_sinkhole():
  sinkholed_domains = sinkhole_datastore.find()
  return render_template('manage_sinkhole.html', sinkholed_domains=sinkholed_domains)


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
  if checkSinkhole(domain):
    print('sinkhole')
    a = bhAnswer
    a['Answer'][0]['name'] = domain
    return jsonify(a)
  url = googleDNSUrl % (domain, requestType)
  answer = requests.get(url)
  return jsonify(answer.json())


def checkSinkhole(domain):
  print('Looking for domain: %s' % domain)
  ed = tldextract.extract(domain)
  rootDomain = "{}.{}".format(ed.domain, ed.suffix)
  d = sinkhole_datastore.find_one({
    "domain": rootDomain
  })
  if d is not None:
    if "*" in d.get('rules') or ed.subdomain in d.get('rules'):
      return True
  return False


if __name__ == '__main__':
  app.run()
