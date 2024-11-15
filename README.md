# API Documentation


## Base URL
```
https://chipinai-backend.onrender.com
```


## Endpoints

### 1. User Registration

**Endpoint:** `/register`

**Method:** `POST`

**Request:**
    -   Body (JSON)
```json
{
    "email": "string",
    "firstName": "string",
    "password": "string",
    "confirm_password": "string
}
```

**Functionality:**
- Registers a new user
- sends a confirmation email to the user

**Response:**

- 201:
  - Body (JSON)
```json
{
    "message": "Verification mail sent",
    "user_data": {
        "id": "string",
        "username": "string",
        "email": "string",
        "createdAt": "string"
    }
}
```
- 400:
```json
{
    "error": "Email already exists."
}
```
- 400:
```json
{
    "error": "Passwords don't match"
}
```

### 2. Confirm Email

**Endpoint:** `/confirm_email/<token>`

**Method:** `GET`

**Request:**
- No request body

**Functionality:**
- Confirms the user's email using email token
- Updates the user's status to active
- should login the user automatically

**Response:**
- 200
  - (JSON)
```json
{
    "message": "Email confirmed! You can now login!",
    "jwt_token": "string",
    "user_data": {
        "id": "string",
        "username": "string",
        "email": "string"
    }
}
```

- 200
  - if user already verfied
```json
{
    "message": "Account already confirmed. Please login!"
}
```

- 400:
  - token expired/ invalid
```json
{
    "error": "Invalid or Expired token"
}
```

- 400
  - User with email doesn't exist
```json
{
    "error": "Invalid email! Please signup"
}
```

### 3. User Login

**Endpoint:** `/login`

**Method:** `POST`

**Request:**
- (JSON)
```json
{
    "email": "string",
    "password": "string"
}
```

**Response:**
- 200
```json
{
    "message": "Logged in successfully",
    "jwt_token": "string",
    "user_data": {
        "id": "string",
        "username": "string",
        "email": "string"
    }
}
```
- 400
```json
{
  "error": "Incorrect password"
}
```
```json
{
  "error": "User does not exist"
}
```
```json
{
  "error": "Email not verified! Please verify your email"
}
```

### 4. User logout

**Endpoint:** `/logout`

**Method:** `GET`

**Headers:**
```
    "x-access-token": "string"
```

**Response:**
- 200
  - (JSON)
```json
{
  "message": "Logged out successfully"
}
```
- 400
```json
{
  "message": "Token is missing!"
}
```

### 5. Forgot password

**Endpoint:** `/forgot_password`

**Method:** `POST`

**Request:**
- (JSON)
```json
{
    "email": "string"   
}
```

**Functioanlity:**
- sends password reset link to user's email

**Response:**
- 200
```json
{
    "message": "Password reset link sent",
    "user_data": {
        "email": "string",
        "firstName": "string"
    }   
}
```
- 400
```json
{
    "error": "User does not exist"
}
```

### 6. Reset Password

**Endpoint:** `/reset_password/<token>`

**Method:** `POST`

**Request:**
- (JSON)
```json
{
    "password": "string",
    "confirm_password": "string"
}
```

**Response:**
- 200
```json
{
    "message": "Password reset successfully"
}
```
- 400
```json
{
    "error": "Invalid or expired token"
}
```
```json
{
    "error": "Passwords don't match"
}
```
```json
{
    "error": "User does not exist"
}
```

### 7. User settings

**Endpoint:** `/settings`

**Method:** `PUT`


**Headers:**
```
    "x-access-token": "string"
```

**Requests:**

- (JSON)
- optional fields
```json
{
  "email": "string",
  "firstName": "string",
  "password": "string",
  "confirm_password": "string"
}
```

**Response:**
- 200
```json
{
  "message": "Settings updated successfully"
}
```
- 400
```json
{
    "error": "User not found"
}
```
```json
{
    "error": "Email already exists"
}
```
```json
{
    "error": "Passwords don't match"
}
```

### 8. Home page

**Endpoint:** `/`

**Method:** `GET`


**Headers**
```
    "x-access-token": "string"
```


**Response:**
- 200
```json
{
  "recommendations": [
    {
            "Bars": 0,
            "Burgers": 0,
            "Chinese": 0,
            "GoodForKids": 1,
            "HasTV": 0,
            "Indian": 0,
            "Irish": 0,
            "Italian": 0,
            "Japanese": 0,
            "Mexican": 0,
            "NoiseLevel": 2.0,
            "OutdoorSeating": 1,
            "Pizza": 0,
            "RestaurantsGoodForGroups": 1,
            "RestaurantsPriceRange2": 1.0,
            "RestaurantsReservations": 0,
            "RestaurantsTakeOut": 1,
            "Sandwiches": 1,
            "Seafood": 0,
            "Steakhouses": 0,
            "Thai": 0,
            "WiFi": 1,
            "alcohol": 0,
            "attire": 0.0,
            "casual": 1,
            "classy": 0,
            "divey": 0,
            "hipster": 0,
            "image_url": "http://0.0.0.0:8080/static/images/placeholder_restaurant.png",
            "intimate": 0,
            "restaurant_name": "Sunny Side Deli",
            "review_count": 292,
            "romantic": 0,
            "stars": 4.0,
            "touristy": 0,
            "trendy": 0,
            "upscale": 0
        },
  ],
  "previous_sessions": [
                    {
            "session_name": "string",
            "session_positions": [          
                {
                    "buyer": "string",
                    "item": "string",
                    "price": "int"
                },
            ],
            "total": "float",
            "admin_id": "string",
            "created_at": "string",
            "receipt": "list(list())",
            "status": "string",
            "participants": ["string"]
        }
    ]
}
```


### 9. Get User Profile

**Endpoint:** `/profile`

**Method:** `GET`


**Headers**
```
    "x-access-token": "string"
```

**Response:**
- 200
```json
{
    "user": {
        "user_id": "string",
        "email": "string",
        "firstName": "string"
    }
}
```
- 404
```json
{
    "error": "User not found"
}
```

### 10. Scan image

**Endpoint:** `/scan_image`

**Method:** `GET`

**Headers**
```
    "x-access-token": "string"
```

**Response:**
- 200
```json
{
    "message": "Scan image endpoint ready"
}
```

### 11. Upload image

**Endpoint:** `/upload_image`

**Method:** `POST`

**Headers**
```
    "x-access-token": "string"
```

**Form Data:**
- using request.files["image"]
```
    "image": "file"
```

**Functionality:**
- processes the image using OCR
- calls `/create_session`

**Response:**
- 200
```json
{
    "message": "Image uploaded successfully",
    "itemName": "string",
    "session_id": "string"
}
```
- 400
```json
{
    "error": "Failed to upload image"
}
```

### 12. Get old sessions

**Endpoint:** `/get_old_sessions`

**Method:** `GET`

**Headers**
```
    "x-access-token": "string"
```

**Response:**
- 200
```json
    "sessions_list": [
        {
            "session_name": "string",
            "positions": "string",
            "total_for_person": "float",
            "total": "float",
            "created_at": "string"
        }
    ]
```


### 13. Create session

**Endpoint:** `/create_session`

**Method:** `POST`

**Headers**
```
    "x-access-token": "string"
```

**Request:**
- (JSON)
```json
{
    "restaurantName": "string",
    "restaurantDetails": "list",
    "receipt": "list(list())"
}
```

**Functionality:**
- creates a session
- calls `socketio.emit('session_created')`
- calls `socketio.emit('user_joined')` -> for the admin

**Response:**
- 201
```json
    "message": "Session created",
    "session_id": "string",
    "session": {
        "session_name": "string",
        "session_positions": [          // will be empty atp
            {
                "buyer": "string",
                "item": "string",
                "price": "int"
            },
        ],
        "total": "float",
        "admin_id": "string",
        "created_at": "string",
        "receipt": "list(list())",
        "status": "string",
        "participants": ["string"]
    },
    "restaurantDetails": "list"
```

### 14. Get session (specific)

**Endpoint:** `/get_session/<session_id>`

**Method:** `GET`

**Headers**
```
    "x-access-token": "string"
```

**Path Parameters:**
- `session_id`: `string`


**Response:**
- 200
```json
    "session_data": {
        "session_name": "string",
        "isClosed": "Bool",
        "positions": [          
            {
                "buyer": "string",
                "item": "string",
                "price": "int"
            },
        ],
        "total_for_person": "float",
        "total": "float",
        "participants": ["string"],
        "created_at": "string",
        "receipt": "list(list())",
    }
```
- 404
```json
{
    "error": "Session not found"
}
```


### 15. Join session

**Endpoint:** `/join_session`

**Method:** `POST`

**Request:**
- (JSON)
```json
{
    "session_id": "string",
    "user_id": "string"    
}
```

**Functionality:**
- Join a session by user ID
- call `socketio.emit('user_joined')`

**Response:**
- 200
```json
    "message": "Joined session successfully"
```
- 404
```json
{
    "error": "Session not found"
}
```
- 400
```json
{
    "message": "User is already part of the session"
}
```

### 16. Update session

**Endpoint:** `/update_session`

**Method:** `PUT`

**Headers**
```
    "x-access-token": "string"
```

**Request:**
- (JSON)
```json
{
    "session_id": "string",
    "positionIndex": "int",
    "itemName": "string",
    "amount": "int"
}
```

**Functionality:**
- Update a session by session ID
- call `socketio.emit('session_updated')`


**Response:**
- 200
```json
    "message": "Session updated successfully"
```

- 404
```json
{
    "error": "Session not found"
}
```
```json
{
    "error": "Position not found"
}
```

### 17. Delete Session

**Endpoint:** `/delete_session/<session_id>`

**Method:** `DELETE`

**Headers**
```
    "x-access-token": "string"
```

**Path Parameters:**
- `session_id`: `string`

**Functionality:**
- Delete a session by session ID
- calls `socketio.emit('session_deleted')`

**Response:**
- 200
```json
    "message": "Session deleted successfully"
```
- 403
```json
{
    "error": "Only the session admin can delete the session"
}
```
- 404
```json
{
    "error": "Session not found"
}
```

### 18. Create Link

**Endpoint:** `/create_link/<session_id>`

**Method:** `GET`

**Headers**
```
    "x-access-token": "string"
```

**Path Parameters:**
- `session_id`: `string`


**Response:**
- 200
```json
    "message": "Link created successfully",
    "link": "request.host_url + `join_link/{session_id}`"
```
- 403
```json
{
    "error": "Only the session admin can create the link"
}
```
- 404
```json
{
    "error": "Session not found"
}
```

### 19. Join Link

**Endpoint:** `/join_link/<session_id>`

**Method:** `GET`


**Path Parameters:**
- `session_id`: `string`

**Request:**
- (JSON)
```json
{
    "user_id": "string" // will have to generate random if user not logged in
}
```

**Functionality:**
- user joins the session
- calls `socketio.emit('user_joined')`

**Response:**
- 200
```json
    "message": "Joined session successfully"
```
- 404
```json
{
    "error": "Session not found"
}
```

### 20. Delete Account

**Endpoint:** `/delete_account`

**Method:** `DELETE`


**Headers**
```
    "x-access-token": "string"
```


**Response:**
- 200
```json
    "message": "Account deleted successfully"
```


### 21. Get Admin

**Endpoint:** `/get_admin/<session_id>`

**Method:** `GET`


**Path Parameters:**
- `session_id`: `string`


**Response:**
- 200
```json
{
    "admin": {
        "id": "string",
        "email": "string",
        "firstName": "string"
    }
}
```
- 400
```json
{
    "error": "Session ID is required"
}
```
- 404
```json
{
    "error": "Session not found"
}
```
- 404
```json
{
    "error": "Admin not found"
}
```


### 22. Monthly report

**Endpoint:** `/monthly_report`

**Method:** `GET`


**Headers**
```
    "x-access-token": "string"
```


**Response:**
- 200
```json
{
    "expenditure": "int"
}
```
- 400
```json
{
    "error": "User not found"
}
```

## SocketIO Events

### 1. Session created
- `socketio.emit('session_created', data)`

```json
data = {
    "session": {
        "session_name": "string",
        "session_positions": [],
        "total": 0,
        "admin_id": "string",
        "created_at": "string",
        "receipt": "string",
        "status": "string",
        "participants": ["string"]
    },
    "session_id": "string"
}
```

- emits -> `emit('session_created_announcement', data, room=session_id)`


### 2. User joined
- `socketio.emit('user_joined', data)`

```json
data = {
    "session_id": "string",
    "user_id": "string"
}
```

- emits -> `emit('user_joined_announcement', data, room=session_id)`


### 3. Session updated
- `socketio.emit('session_updated', data)`

```json
data = {
    "session_id": "string",
    "positions": "list",
    "total": "float",
}
```
- emits -> `emit('session_updated_announcement', data, room=session_id)`


### 4. Session deleted
- `socketio.emit('session_deleted', data)`

```json
data = {
    "session_id": "string"
}
```
- emits -> `emit('session_deleted_announcement', data, room=session_id)`
