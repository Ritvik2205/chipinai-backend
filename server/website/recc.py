from flask import Flask, request, Blueprint, jsonify, url_for
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import os
import joblib

recc = Blueprint('recc', __name__)

nrows = 100000
pd.set_option("display.precision", 1)

scalerUser = StandardScaler()
scalerItem = StandardScaler()
scalerTarget = MinMaxScaler((-1, 1))

current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, "../final_item_features.csv")

item_train_df = pd.read_csv(file_path, nrows=nrows, dtype={'column_name': 'float32'})
item_train_df = item_train_df.apply(pd.to_numeric, errors='coerce')
item_train_df.fillna(0, inplace=True)
num_item_features = item_train_df.shape[1]
item_train = item_train_df.to_numpy()
item_train = item_train.astype(np.float32)
item_train_unscaled = item_train.copy()
item_train = scalerItem.fit_transform(item_train)
item_train, item_test = train_test_split(item_train, train_size=0.7, shuffle=True, random_state=1)

class UserNN(nn.Module):
    def __init__(self, num_user_features, num_outputs):
        super(UserNN, self).__init__()
        self.fc1 = nn.Linear(num_user_features, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, num_outputs)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        return self.fc3(x)

class ItemNN(nn.Module):
    def __init__(self, num_item_features, num_outputs):
        super(ItemNN, self).__init__()
        self.fc1 = nn.Linear(num_item_features, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, num_outputs)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        return self.fc3(x)
    
class RecommendationModel(nn.Module):
    def __init__(self, user_nn, item_nn):
        super(RecommendationModel, self).__init__()
        self.user_nn = user_nn
        self.item_nn = item_nn

    def forward(self, user_input, item_input):
        vu = self.user_nn(user_input)
        vu = nn.functional.normalize(vu, dim=1)
        vm = self.item_nn(item_input)
        vm = nn.functional.normalize(vm, dim=1)
        output = torch.bmm(vu.unsqueeze(1), vm.unsqueeze(2)).squeeze()
        return output
    
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
num_user_features = 31
num_item_features = 35
num_outputs = 64

user_nn = UserNN(num_user_features, num_outputs).to(device)
item_nn = ItemNN(num_item_features, num_outputs).to(device)
model = RecommendationModel(user_nn, item_nn).to(device)

model_path = os.path.join(current_dir, "../model_weights.pth")
model.load_state_dict(torch.load(model_path, map_location=device))
model.eval()



def get_recommendations(new_user):
    scalerUser = joblib.load("scaler_user.pkl")
    new_user_scaled = scalerUser.transform(new_user)

    new_user_tensor = torch.tensor(new_user_scaled, dtype=torch.float32).to(device)
    item_tensor = torch.tensor(item_train, dtype=torch.float32).to(device)

    new_user_batch = new_user_tensor.repeat(item_tensor.shape[0], 1)

    predictions = model(new_user_batch, item_tensor)

    scalerTarget = joblib.load('scaler_target.pkl')
    predictions_inverse = scalerTarget.inverse_transform(predictions.reshape(-1, 1).detach().cpu().numpy())
    top_10_indices = predictions_inverse.flatten().argsort()[-10:][::-1]
    
    top_10_df = item_train_df.iloc[top_10_indices].copy()

    restaurant_names = ["Lotus Garden Bistro", "Sunny Side Deli", "The Velvet Taproom", "The Pizza Patio", "Brick Oven & Brews", "Cornerstone Subs", "Tranquil Bites Café", "Solo Spoons Eatery", "Spicy Thai Express", "Fiesta Grill & Cantina"]
    top_10_df["restaurant_name"] = restaurant_names
    
    image_urls = []
    for restaurant_name in restaurant_names:
        image_filename = restaurant_name.replace(" ", "_").lower() + ".png"
        image_path = os.path.join(current_dir, "images", image_filename)
        if os.path.exists(image_path):
            image_url = url_for('static', filename=os.path.join("images", image_filename), _external=True)
        else:
            image_url = url_for('static', filename=os.path.join("images", "placeholder_restaurant.png"), _external=True)
        image_urls.append(image_url)

    top_10_df["image_url"] = image_urls    
    return(top_10_df)

@recc.route('/get-recc', methods=['GET'])
def get_recc():
    user_id = request.args.get('userId')
    # Logic for recommendation based on user history
    # Placeholder response for now
    return jsonify({'recommendations': 'Personalized restaurant recommendations based on history'}), 200