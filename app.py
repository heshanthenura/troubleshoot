from flask import Flask, request,jsonify,make_response
from flask_cors import CORS 
from flask_bcrypt import Bcrypt 

import datetime
from datetime import timezone
import jwt
from functools import wraps
import bcrypt


app = Flask(__name__)

bcrypt = Bcrypt(app) 

CORS(app,supports_credentials=True)
app.config['SECRET_KEY'] = '2003213@Heshanthenuraletmein'

def validate_token(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return {"valid": False, "message": "Authorization header is missing or invalid"}, 400
    token = auth_header.split(" ")[1] 
    if not token:
        return {"valid": False, "message": "Token is missing"}, 400
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return {"valid": True, "username": data['username'], "role": data['role']}, 200
    except jwt.ExpiredSignatureError:
        return {"valid": False, "message": "Token has expired"}, 401
    except jwt.InvalidTokenError:
        return {"valid": False, "message": "Invalid token"}, 401

def role_required(required_roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            validation_result, status_code = validate_token(auth_header)
            if not validation_result["valid"]:
                if validation_result["message"] == "Token has expired":
                    print("Token has expired")
                elif validation_result["message"] == "Invalid token":
                    print("Invalid token")
                return jsonify(validation_result), status_code
            token_data = validation_result
            user_role = token_data.get('role')
            if required_roles and user_role not in required_roles:
                return jsonify({"message": "User does not have the required role"}), 403
            return f(*args, token_data=token_data, **kwargs)
        return wrapper
    return decorator

def authorize_token(data, required_roles):
    user_role = data.get('role')
    print(user_role)
    if user_role not in required_roles:
        return {"authorized": False, "message": "User does not have the required role"}, 403
    return {"authorized": True}, 200

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            validation_result, status_code = validate_token(auth_header)
            if not validation_result["valid"]:
                return jsonify(validation_result), status_code

            token_data = validation_result
            user_role = token_data.get('role')
            if user_role not in required_roles:
                return jsonify({"message": "User does not have the required role"}), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/')
def home():
    return "Welcome to the Flask API!"

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    user_data = get_user_by_username(username)
    if user_data:
        if bcrypt.check_password_hash(user_data.get('password'), password) :
            print(user_data)
            token = jwt.encode(
                {'username': username, 'role': user_data.get('role'), 'exp': datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=24)},
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            return jsonify({"message": "Login successful", "token": token})
        return jsonify({"message": "Invalid password"}), 401
    return jsonify({"message": "User not found"}), 404

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    confPassword = request.json.get('confPassword')
    print (f"{username} {password} {confPassword}")
    if not username or not password or not confPassword:
        return jsonify({"message": "Missing required fields"}), 400
    if password != confPassword:
        return jsonify({"message": "Passwords do not match"}), 400
    if (get_user_by_username(username) != None) or (get_userApprove_by_username(username) != None):
        return jsonify({"message": "Username already exists"}), 400
    if len(username) < 6: 
        return jsonify({"message": "Username must be at least 6 characters long"}), 400
    if len(password) < 6: 
        return jsonify({"message": "Password must be at least 6 characters long"}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    add_document_to_approve(
        {
            "username":username,
            "password":hashed_password,
            "role":"USER"
        }
    )
    return jsonify({"message": "Registration successful"}), 200

@app.route('/approveUser',methods=['POST'])
# @role_required(['ADMIN'])
def approve_user():
    print(request.json)
    if approveUser(request.json.get('id')):
        return jsonify({"message": "User approves successfully"}), 200
    return jsonify({"message": "error approving user"}), 400

@app.route('/toApprove',methods=['GET'])
# @role_required(['ADMIN'])
def toAprrove():    
    return get_all_toApprove()    

@app.route('/disapproveUser',methods=['POST'])
# @role_required(['ADMIN'])
def disapprove_user():
    print(request.json)
    if remove_user_from_toApprove(request.json.get('id')):
        return jsonify({"message": "User disapproves successfully"}), 200
    return jsonify({"message": "error disapproving user"}), 400

@app.route('/users',methods=['GET'])
# @role_required(['ADMIN'])
def users():    
    return get_all_users()    

@app.route('/deluser',methods=['POST'])
# @role_required(['ADMIN'])
def delete_users():
    if remove_user(request.json.get('id')):
        return jsonify({"message": "User remove successfully"}), 200
    return jsonify({"message": "User remove unsuccessfully"}), 400   


@app.route('/validate', methods=['GET'])
def validate():
    auth_header = request.headers.get('Authorization')
    print("validate")
    print(request.headers)
    validation_result, status_code = validate_token(auth_header)
    if not validation_result["valid"]:
        return jsonify(validation_result), status_code
    return jsonify(validation_result), 200

@app.route('/protected', methods=['GET'])
@role_required(['ADMIN'])
def protected():
    return jsonify({"message": "Access granted"}), 200

@app.route('/textgen',methods=['POST'])
@role_required(['ADMIN','USER'])
def generateText():   
    return "text gen"

if __name__ == '__main__':
    app.run(debug=True,port=8080)
