from flask import Flask, request
app = Flask(__name__)

from heart import heart
from random import randint
import os
import sys

DIRECTORY = "tmp/"
SAVED_DIR = "saved/"

classifier = heart()

def finish(fileName, result):
  os.remove(DIRECTORY + fileName)
  return str(result)

@app.route("/check", methods = ['POST'])
def checkImage():
  domain = request.json['domain']
  url = request.json['url']

  #Cache before hitting FLANN
  if(domain in classifier.safe):
    return str(False)
  elif(domain in classifier.malicious):
    return str(True)

  fileName = str(randint(1,sys.maxint)) + ".jpeg"
  base64Img = request.json['img_data']
  img = base64Img.decode('base64')
  with open(DIRECTORY+fileName, 'w') as f:
    f.write(img)

  match = classifier.getDescriptors(fileName, domain, url)

  return finish(fileName, match)

@app.route("/safe", methods = ['POST'])
def markSafe():
  clientId = request.json['clientId']
  url = request.json['url']
  classifier.markSafe(clientId, url)

@app.route("/report", methods = ['GET'])
def reportMalicious():
  url = request.args['url']
  classifier.reportMalicious(url)
  return "Thanks!"

if __name__ == "__main__":
    app.run("ec2-35-165-195-195.us-west-2.compute.amazonaws.com", 5001)
