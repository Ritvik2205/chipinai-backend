from flask import Flask, jsonify, request, Blueprint
from . import mongo, client, db, users_collection, sessions_collection, mail, socketio
import datetime
from bson.objectid import ObjectId
from flask_login import login_user, login_required, logout_user, current_user
from urllib.parse import urlencode, urljoin
from .auth import token_required
from flask_socketio import emit 
import jwt
from os import getenv
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = getenv("SECRET_KEY")

sessions = Blueprint('sessions', __name__)


@sessions.route('/create_session', methods=['POST'])
@token_required
def create_session(current_user_id):
    data = request.get_json()
    restaurant_details = data.get("restaurantDetails")
    current_datetime = datetime.datetime.now()
    date_part = current_datetime.strftime("%Y-%m-%d")
    time_part = current_datetime.strftime("%H:%M:%S")
    session_name = f"{date_part} - {time_part} - {data.get('restaurantName')}"
    receipt = data.get("receipt")
    session_positions = [{} for _ in range(len(receipt))]
    total = 0
    admin_id = str(current_user_id)
    created_at = str(datetime.datetime.now())    
    status = "inactive"
    participants = [str(current_user_id)]
    session = {
        "session_name": session_name,
        "session_positions": session_positions,
        "total": float(total),
        "admin_id": admin_id,
        "created_at": created_at,
        "receipt": receipt,
        "status": status,
        "participants": participants
    }
    session_id = str(sessions_collection.insert_one(session).inserted_id)      
    socketio.emit('session_created', {"session": dict(session), "session_id": session_id})

    socketio.emit("user_joined", {"session_id": session_id, "user_id": current_user_id})
    session["_id"] = str(session_id)    

    return jsonify({"message": "Session created", "session_id": session_id, "session": dict(session), "restaurantDetails": restaurant_details}), 201


@sessions.route('/get_old_sessions', methods=['GET'])
@token_required
def get_old_sessions(current_user_id):
    sessions = list(sessions_collection.find({"participants": current_user_id}))

    response_list = []
    for session in sessions:
        if session.get("status") == "closed":
            session_data = {
                "session_name": session["session_name"],
                "positions": session["session_positions"],
                "total_for_person": float(calculate_total_for_user(current_user_id, session)),
                "total": float(session["total"]),
                "created_at": str(session["created_at"]),
            }
            response_list.append(session_data)
    return jsonify({"sessions_list": response_list}), 200


def calculate_total_for_user(user_id, session):
    total = 0
    for position in session['session_positions']:
        if position.get('buyer') and position.get('price'):
            if position['buyer'] == user_id:
                total += position['price']
    return total


@sessions.route('get_session/<session_id>', methods=['GET'])
def get_session(session_id):    
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})
    current_user_id = request.get_json().get('user_id')
    if session:
        status = session.get("status")
        if status == "active":
            pass
        else:
            token = request.headers.get("x-access-token")
            if not token:
                return jsonify({"error": "Token is missing"}), 401
            
            try:
                current_user_id = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["user_id"]
            except:
                return jsonify({"error": "Invalid token"}), 401
            
            if session["admin_id"] != current_user_id:
                return jsonify({"error": "Only the session admin can access this session"}), 403
            
        session_data = {
            "session_name": session["session_name"],
            "status": session.get("status"),
            "positions": session["session_positions"],
            "total_for_person": float(calculate_total_for_user(current_user_id, session)),
            "total": float(session["total"]),
            "participants": session["participants"],
            "admin_id": session["admin_id"],
            "created_at": session["created_at"],
            "receipt": session["receipt"]
        }
        return jsonify({"session_data": session_data}), 200
    else:
        return jsonify({"error": "Session not found"}), 404
    

@sessions.route('/join_session', methods=['POST'])
def join_session():
    data = request.get_json()
    session_id = data.get('session_id')
    current_user_id = data.get('user_id')
        
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})
    
    if session:
        if current_user_id in session['participants']:
            return jsonify({'message': 'User is already part of the session'}), 400
                
        sessions_collection.update_one(
            {'_id': ObjectId(session_id)},
            {'$push': {'participants': current_user_id}}
        )
        socketio.emit("user_joined", {"session_id": session_id, "user_id": current_user_id})
        
        return jsonify({'message': 'Joined session successfully'}), 200
    else:
        return jsonify({'message': 'Session not found'}), 404
    

@sessions.route('/update_session', methods=['PUT'])
@token_required
def update_session(current_user_id):
    data = request.get_json()
    session_id = data.get("sessionId")
    updated_session = data.get("session")

    session = sessions_collection.find_one({'_id': ObjectId(session_id)})

    if session:        
        
        total = sum([position["price"] for position in updated_session["session_positions"] if position.get("price")])
        updated_session["total"] = total
        sessions_collection.update_one(
            {"_id": ObjectId(session_id)},
            {"$set": updated_session}
        )
        socketio.emit("session_updated", {"session_id": session_id, "positions": updated_session["session_positions"], "total": total})
        return jsonify({"message": "Session updated successfully", "new_total": total}), 200
    else:
        return jsonify({"error": "Session not found"}), 404


@sessions.route('/delete_session/<session_id>', methods=['DELETE'])
@token_required
def delete_session(current_user_id, session_id):    
    session = sessions_collection.find_one({"_id": ObjectId(session_id)})

    if session:
        # Check if the current user is the session admin
        if session["admin_id"] == current_user_id:
            # Delete the session
            sessions_collection.delete_one({"_id": ObjectId(session_id)})            
            socketio.emit("session_deleted", {"session_id": session_id})
            return jsonify({"message": "Session deleted successfully"}), 200
        else:
            return jsonify({"error": "Only the session admin can delete the session"}), 403
    else:
        return jsonify({"error": "Session not found"}), 404
    
@sessions.route('create_link/<session_id>', methods=['GET'])
@token_required
def create_link(current_user_id, session_id):
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})

    if session:
        if current_user_id == session['admin_id']:
            base_url = request.host_url
            join_path = f"join_link/{session_id}"
            link = urljoin(base_url, join_path)
            return jsonify({"message": "Link created successfully", "link": link}), 200
        else:
            return jsonify({"error": "Only the session admin can create the link"}), 403
    else:
        return jsonify({"error": "Session not found"}), 404
    

@sessions.route('/confirm_bill/<session_id>', methods=['PUT'])
@token_required
def confirm_bill(current_user_id, session_id):
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})

    if session:
        if current_user_id == session['admin_id']:
            sessions_collection.update_one(
                {'_id': ObjectId(session_id)},
                {'$set': {'status': 'active'}}
            )
            return jsonify({"message": "Bill confirmed successfully"}), 200
        else:
            return jsonify({"error": "Only the session admin can confirm the bill"}), 403
    else:
        return jsonify({"error": "Session not found"}), 404


@sessions.route('/close_session/<session_id>', methods=['PUT'])
@token_required
def close_session(current_user_id, session_id):
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})

    if session:
        if current_user_id == session['admin_id']:
            sessions_collection.update_one(
                {'_id': ObjectId(session_id)},
                {'$set': {'status': 'closed'}}
            )
            return jsonify({"message": "Session closed successfully"}), 200
        else:
            return jsonify({"error": "Only the session admin can close the session"}), 403
    else:
        return jsonify({"error": "Session not found"}), 404
    


@sessions.route('join_link/<session_id>', methods=['GET'])
def join_link(session_id):
    data = request.get_json()
    current_user_id = data.get('user_id')
    session = sessions_collection.find_one({'_id': ObjectId(session_id)})

    if session:
        if current_user_id in session['participants']:
            return jsonify({'message': 'User is already part of the session'}), 400
                
        sessions_collection.update_one(
            {'_id': ObjectId(session_id)},
            {'$push': {'participants': current_user_id}}
        )
        socketio.emit("user_joined", {"session_id": session_id, "user_id": current_user_id})
        return jsonify({'message': 'Joined session successfully'}), 200
    else:
        return jsonify({'message': 'Session not found'}), 404