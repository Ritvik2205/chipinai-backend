from flask import Flask, request, jsonify, Blueprint, url_for
from . import sessions_collection, users_collection
from .auth import token_required
from .recc import get_recommendations
from .ocr import processReceipt
import numpy as np
import requests
from bson.objectid import ObjectId
import datetime
from PIL import Image
import cv2 as cv
import os

views = Blueprint('views', __name__)


@views.route('/', methods=['GET'])
@token_required
def index(current_user_id):
    user_id = str(current_user_id)

    previous_sessions = list(sessions_collection.find({"participants": user_id, "status": "closed"}).sort("created_at", -1).limit(4))
    for session in previous_sessions:
        session["_id"] = str(session["_id"]) # Convert ObjectId to string


    new_user = np.array([[3, 4.0, 4.0, 0.0, 0.0, 0.0, 0.0, 4.0, 4.0, 0.0, 0.0, 4.0, 0.0, 4.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 4.0, 0.0, 4.0, 0, 0, 0, 2.0, 0.6666666666666666, 0.6666666666666666]])
    recommendations = get_recommendations(new_user)
    recommendations_dict = recommendations.to_dict(orient="records")
    
    return jsonify({"recommendations": recommendations_dict, "previous_sessions": previous_sessions}), 200


@views.route('/profile', methods=['GET'])
@token_required
def get_user(current_user_id):
    user_id = str(current_user_id)
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        user_data = {
            "user_id": str(user["_id"]),
            "email": user["email"],
            "firstName": user["firstName"],
        }
        return jsonify({"user": user_data}), 200
    else:
        return jsonify({"error": "User not found"}), 404

@views.route("/scan_image")
@token_required
def scan_image():
    return jsonify({"message": "Scan image endpoint ready"}), 200

@views.route("/upload_image", methods=["POST"])
@token_required
def upload_image(current_user_id):
    if 'image' not in request.files:
        return jsonify({"error": "No image file provided"}), 400
    image = request.files['image']
    # print(type(image))
    try:
        img = Image.open(image)        
        # img = img.convert('RGB')
        img = np.array(img)
        # img_dir = 'server/website/static'
        # if not os.path.exists(img_dir):
        #     os.makedirs(img_dir)
        
        # # Save the image as a JPG file
        # img_filename = f"receipt.jpg"
        # img_path = os.path.join(img_dir, img_filename)

        # img.save(img_path, 'JPEG')
        # # img = cv.cvtColor(img, cv.COLOR_RGB2BGR)
        # image2 = cv.imread("./static/receipt.jpg")
    except Exception as e:
        return jsonify({"error": f"Failed to convert image to JPG: {str(e)}"}), 400
        
    restaurant_details, receipt_text = processReceipt(img)

    session_data = {
        "restaurantName": restaurant_details[0],
        "restaurantDetails": restaurant_details,
        "receipt": receipt_text
    }
    session_url = url_for("sessions.create_session", _external=True)
    headers = {'x-access-token': request.headers.get("x-access-token")}
    response = requests.post(session_url, json=session_data, headers=headers)

    if response.status_code == 201:
        session_id = response.json().get('session_id')
        return jsonify({"message": "Image uploaded successfully", "session_id": session_id}), 200
    else:
        return jsonify({"error": "Failed to upload image"}), 400


@views.route("/monthly_report", methods=["GET"])
@token_required
def get_monthly_report(current_user_id):
    user_id = str(current_user_id)
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    one_month_ago = datetime.datetime.now() - datetime.timedelta(days=30)
    expenditure = 0

    sessions = list(sessions_collection.find({"participants": user_id}))
    for session in sessions:
        # convert string to datetime
        created_at = datetime.datetime.strptime(session["created_at"], "%Y-%m-%d %H:%M:%S.%f")
        if created_at >= one_month_ago:
            expenditure += sum([position["price"] for position in session["session_positions"] if position.get("buyer") == user_id])

    return jsonify({"expenditure": expenditure}), 200