from flask import Flask, request
from flask_restful import Resource, Api 
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition
users = db["Users"]

def userExist(username):
    return False if users.find({"Username": username}).count() == 0 else True
class Register(Resource):
    def post(self):
        
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        if userExist(username):
            retJSON = {
                "status": 301,
                "msg": "User with that username is already registered."
            }
            return retJSON

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 6
        })

        retJSON = {
            "status": 200,
            "msg": "You are successfully registered."
        }
        return retJSON

def verifyCredentials(username, password):
    if not userExist(username):
        # returning True because we need two variables. True is for the error
        return generateReturnDictionary(301, "Not an existing user."), True
    
    correct_pw = verify_pw(username, password)

    if not correct_pw:
        return generateReturnDictionary(302, "Invalid password."), True

    return None, False

def verify_pw(username, password):
    if not userExist(username):
        return False

    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    return True if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw else False

def generateReturnDictionary(status, msg):
    retJSON = {
        "status": status,
        "msg": msg
    }
    return retJSON

class Classify(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        # if there is an error, error is going to be true and retJSON will not be null, but if everything is ok, error will be flase and retJSON is None
        retJSON, error = verifyCredentials(username, password)
        if error: 
            return retJSON
        
        tokens = users.find({
            "Username": username
        })[0]["Tokens"]

        if not tokens: 
            return generateReturnDictionary(303, "You don't have enough tokens.")

        # getting an image form the url
        r = requests.get(url)
        retJSON = {}
        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen("python3 classify_image.py --model_dir=. --image_file=./temp.jpg") # model_dir is where inception-2015-12-05.tgz
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                retJSON = json.load(g)

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": tokens-1
            }
        })

        return retJSON

class Refill(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["admin_pw"]
        amount = postedData["amount"]

        if not userExist(username):
            return generateReturnDictionary(301, "Not an existing user.")

        correct_admin_pw = "abc123"

        if not password == correct_admin_pw:
            return generateReturnDictionary(304, "Invalid administrator password.")

        users.update({
            "Username":username
        }, {
            "$set": {
                "Tokens": amount
            }
        })

        return generateReturnDictionary(200, "Refill was succcessful.")

api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0')