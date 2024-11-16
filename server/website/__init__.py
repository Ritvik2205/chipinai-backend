from flask import Flask
from flask_pymongo import PyMongo, MongoClient
from flask_mail import Mail
from flask_login import LoginManager
from bson.objectid import ObjectId
from flask_cors import CORS
from flask_socketio import SocketIO
from dotenv import load_dotenv
from os import getenv
import ssl  

load_dotenv()

MONGO_DB = getenv("MONGO_DATABASE_NAME")
MONGO_USERS_COLC = getenv("MONGO_USERS_COLLECTION")
MONGO_SESSIONS_COLC = getenv("MONGO_SESSIONS_COLLECTION")

mongo = PyMongo()
client = MongoClient(getenv("MONGO_CLIENT"), tls=True, tlsAllowInvalidCertificates=True)
db = client.MONGO_DB  # Database name
users_collection = db.MONGO_USERS_COLC  # Users collection
sessions_collection = db.MONGO_SESSIONS_COLC  # Sessions collection

mail = Mail()
socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.debug = True
    app.config['SECRET_KEY'] = getenv("SECRET_KEY")

    app.config['MAIL_SERVER'] = getenv("MAIL_SERVER")
    app.config['MAIL_PORT'] = getenv("MAIL_PORT")
    app.config['MAIL_USERNAME'] = getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = getenv("MAIL_PASSWORD")
    app.config['MAIL_USE_TLS'] = getenv("MAIL_USE_TLS").lower() == "true"
    app.config['MAIL_USE_SSL'] = getenv("MAIL_USE_SSL").lower() == "true"
    app.config['MAIL_DEFAULT_SENDER'] = getenv("MAIL_DEFAULT_SENDER")

    app.config["MONGO_URI"] = getenv("MONGO_URI")
    
    CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://chipin-ai.com", "chip-in-ai-web.vercel.app"]}})                      # HACK: temp
    mail.init_app(app)
    mongo.init_app(app)

    from .auth import auth
    from .views import views
    from .sessions import sessions
    from .recc import recc
    from .ocr import ocr

    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(sessions, url_prefix='/')
    app.register_blueprint(recc, url_prefix='/')
    app.register_blueprint(ocr, url_prefix='/')

    socketio.init_app(app)

    from .models import User

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        user = users_collection.find_one({"_id": ObjectId(id)})
        if user: 
            return User(str(user['_id']), user['email'])
        return None

    return app