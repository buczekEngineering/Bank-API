from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.BankTransferDB
users = db["users"]


def generate_json(status_code, msg):
    retJson = {
        "Status Code": status_code,
        "Msg": msg
    }
    return jsonify(retJson)


def user_exists(username):
    if users.find({"username": username}).count() != 0:
        return True
    else:
        return False


def encode_pw(password):
    hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())
    return hashed_pw


def correct_pw(username, password):
    hashed_pw = users.find({"username": username})[0]["password"]
    if bcrypt.hashpw(password.encode("utf8"), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def yourMoney(username):
    return users.find({"username": username})[0]["your_money"]


def yourDebt(username):
    return users.find({"username": username})[0]["debt"]


class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        # if user_exists(username):
        #     return generate_json(301, "Username already exists")

        hashed_pw = encode_pw(password)
        users.insert({"username": username,
                      "password": hashed_pw,
                      "your_money": 0,
                      "debt": 0
                      })
        return generate_json(200, "Register successfully completed!")


class Add(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        if not user_exists(username):
            return generate_json(301, "Invalid username")
        if not correct_pw(username, password):
            return generate_json(302, "Invalid password")

        your_money = users.find({"username": username})[0]["your_money"]
        users.update({"username": username}, {"$set": {"your_money": your_money + amount}})

        return generate_json(200, "You've successfully updated your bank account by {}€.".format(amount))


class Transfer(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]
        transfer_to = postedData["to_whom"]

        if not user_exists(username):
            return generate_json(301, "Invalid username")
        if not correct_pw(username, password):
            return generate_json(302, "Invalid password")
        # validate if the user you are transferring money to, is correct
        if not user_exists(transfer_to):
            return generate_json(305, "The username of your transfer target is not correct.")

        current_money = yourMoney(username)
        if current_money < amount:
            return generate_json(303, "You've not enough money.")

        users.update({"username": username}, {"$set": {"your_money": current_money - amount}})

        users.update({"username": transfer_to},
                     {"$set": {"your_money": users.find({"username": transfer_to})[0]["your_money"] + amount}})

        return generate_json(200, "You've successfully transfered")


class CheckBalance(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        if not user_exists(username):
            return generate_json(301, "Invalid username")
        if not correct_pw(username, password):
            return generate_json(302, "Invalid password")

        current_money = yourMoney(username)
        current_debt = yourDebt(username)
        return generate_json(200, "Current account status: {} and current debt: {}".format(current_money, current_debt))


class TakeLoan(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        if not user_exists(username):
            return generate_json(301, "Invalid username")
        if not correct_pw(username, password):
            return generate_json(302, "Invalid password")
        current_money = yourMoney(username)
        current_debt = yourDebt(username)
        users.update({"username": username}, {"$set": {"debt": current_debt + amount}})
        users.update({"username": username}, {"$set": {"your_money": current_money + amount}})

        return generate_json(200,
                             "The procedure successfully completed! Your current account status is {}€, and debt status is {}€.".format(current_money+amount, current_debt+amount))


class PayLoan(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        amount = postedData["amount"]

        if not user_exists(username):
            return generate_json(301, "Invalid username")
        if not correct_pw(username, password):
            return generate_json(302, "Invalid password")
        current_money = yourMoney(username)
        if current_money < amount:
            return generate_json(303, "You have not enough money!")
        current_debt = yourDebt(username)

        if current_debt == 0:
            return generate_json(305, "You don't have any debt!")
        rest = current_debt - amount
        if rest < 0:
            users.update({"username": username}, {"$set": {"debt": 0,
                                                           "your_money": current_money + rest}})

        users.update({"username": username}, {"$set": {"debt": rest}})
        return generate_json(200, "You've successfully updated your account!")


api.add_resource(Transfer, "/transfer")
api.add_resource(PayLoan, "/payloan")
api.add_resource(TakeLoan, "/takeloan")
api.add_resource(CheckBalance, "/checkbalance")
api.add_resource(Add, "/add")
api.add_resource(Register, "/register")

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
