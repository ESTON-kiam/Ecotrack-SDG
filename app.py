import sys
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import os
import ssl
from functools import wraps
import logging
from dotenv import load_dotenv
import certifi

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Use environment variable for secret key in production
app.secret_key = os.getenv('SECRET_KEY', '861612ceadae2312be7a77fabead3a0d2b7a418cfc5c6a77ece99ec84fde1dbc')


def get_mongo_client():
    """MongoDB connection with multiple fallback strategies"""

    logger.info("Attempting to connect to MongoDB...")

    MONGO_URI = os.getenv('MONGO_URI') or os.getenv('DATABASE_URL')

    if not MONGO_URI:
        MONGO_URI = 'mongodb+srv://engestonbrandonkiama_db_user:nnMzFjnW7Ync3g9P@cluster0.sxdpjue.mongodb.net/ecotrack?retryWrites=true&w=majority&appName=Cluster0'
        logger.info("Using fallback MongoDB URI for local development")

    MONGO_URI = MONGO_URI.strip()
    logger.info(f"Using MongoDB URI: {MONGO_URI[:50]}...")

    # Check if we're running on Render by looking for environment indicators
    is_render = any(key in os.environ for key in ['RENDER', 'RENDER_SERVICE_ID', 'RENDER_EXTERNAL_HOSTNAME'])
    if is_render:
        logger.info("Detected Render deployment environment")

    # Strategy 1: Render-optimized connection (for production)
    if is_render:
        try:
            logger.info("Trying Strategy 1: Render-optimized connection")
            # Use a connection string optimized for Render's infrastructure
            render_uri = MONGO_URI.replace('retryWrites=true&w=majority',
                                           'retryWrites=true&w=majority&ssl=true&tlsAllowInvalidCertificates=true&tlsAllowInvalidHostnames=true')

            client = MongoClient(
                render_uri,
                serverSelectionTimeoutMS=45000,  # Extended for Render
                connectTimeoutMS=45000,
                socketTimeoutMS=45000,
                maxPoolSize=3,  # Conservative pool size for Render
                retryWrites=True,
                maxIdleTimeMS=45000,
                heartbeatFrequencyMS=30000,
                # Render-specific SSL settings
                tls=True,
                tlsAllowInvalidCertificates=True,
                tlsAllowInvalidHostnames=True
            )
            client.admin.command('ping')
            logger.info("✅ Strategy 1 (Render-optimized) successful!")
            return client
        except Exception as e:
            logger.warning(f"Render-optimized strategy failed: {e}")

    # Strategy 2: Try with standard TLS configuration
    try:
        logger.info("Trying Strategy 2: Standard TLS configuration")
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=30000,  # Increased timeout
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            maxPoolSize=10,
            retryWrites=True,
            maxIdleTimeMS=30000,
            heartbeatFrequencyMS=10000
        )
        client.admin.command('ping')
        logger.info("✅ Strategy 2 successful - Connected to MongoDB!")
        return client
    except Exception as e:
        logger.warning(f"Strategy 2 failed: {e}")

    # Strategy 3: Try with SSL context configuration
    try:
        logger.info("Trying Strategy 3: Custom SSL context")
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        client = MongoClient(
            MONGO_URI,
            tls=True,
            ssl_context=ssl_context,
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            maxPoolSize=10,
            retryWrites=True
        )
        client.admin.command('ping')
        logger.info("✅ Strategy 3 successful - Connected to MongoDB!")
        return client
    except Exception as e:
        logger.warning(f"Strategy 3 failed: {e}")

    # Strategy 4: Try with SSL disabled (for local testing only)
    try:
        logger.info("Trying Strategy 4: SSL disabled configuration")

        # Parse the URI and modify it to use standard MongoDB connection
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(MONGO_URI)

        # Create a connection string without SSL requirements
        if 'mongodb+srv' in MONGO_URI:
            # For SRV connections, try with minimal SSL
            client = MongoClient(
                MONGO_URI,
                tls=True,
                tlsAllowInvalidCertificates=True,
                tlsAllowInvalidHostnames=True,
                tlsInsecure=True,
                serverSelectionTimeoutMS=30000,
                connectTimeoutMS=30000,
                socketTimeoutMS=30000,
                maxPoolSize=5,
                retryWrites=True
            )
        else:
            client = MongoClient(MONGO_URI, ssl=False)

        client.admin.command('ping')
        logger.info("✅ Strategy 4 successful - Connected to MongoDB!")
        return client
    except Exception as e:
        logger.warning(f"Strategy 4 failed: {e}")

    # Strategy 5: Try with alternative SSL settings
    try:
        logger.info("Trying Strategy 5: Alternative SSL settings")

        client = MongoClient(
            MONGO_URI,
            ssl=True,
            ssl_cert_reqs=ssl.CERT_NONE,
            ssl_ca_certs=certifi.where(),
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            maxPoolSize=5,
            retryWrites=True,
            authSource='admin'
        )
        client.admin.command('ping')
        logger.info("✅ Strategy 5 successful - Connected to MongoDB!")
        return client
    except Exception as e:
        logger.warning(f"Strategy 5 failed: {e}")

    # Strategy 6: Try with Python SSL settings
    try:
        logger.info("Trying Strategy 6: Python SSL library settings")

        # Set SSL options globally
        ssl._create_default_https_context = ssl._create_unverified_context

        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000,
            maxPoolSize=5,
            retryWrites=True
        )
        client.admin.command('ping')
        logger.info("✅ Strategy 6 successful - Connected to MongoDB!")
        return client
    except Exception as e:
        logger.warning(f"Strategy 6 failed: {e}")

    logger.error("🚫 All MongoDB connection strategies failed.")
    logger.error(f"- Python version: {sys.version}")
    logger.error(f"- Python SSL version: {ssl.OPENSSL_VERSION}")
    logger.error(f"- Certifi CA bundle: {certifi.where()}")
    logger.error("- Consider checking MongoDB Atlas network access settings")
    logger.error("- Verify that your IP address is whitelisted in MongoDB Atlas")

    return None


def init_db():
    global client, db, users, actions

    client = get_mongo_client()
    if client:
        try:
            db = client.ecotrack
            users = db.users
            actions = db.actions
            logger.info("Database collections initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Error initializing database collections: {e}")
            return False
    else:
        logger.error("Failed to connect to MongoDB - app may not work properly")
        return False


# Add a connection retry mechanism
def ensure_db_connection():
    """Ensure database connection is active, reconnect if necessary"""
    global db_available, client, db, users, actions

    if not db_available or client is None:
        logger.info("Attempting database reconnection...")
        db_available = init_db()
        return db_available

    try:
        # Test the connection
        client.admin.command('ping')
        return True
    except Exception as e:
        logger.warning(f"Database connection test failed: {e}")
        logger.info("Attempting database reconnection...")
        db_available = init_db()
        return db_available


db_available = init_db()

# Rest of your code remains the same...
SUSTAINABLE_ACTIONS = {
    'plant_tree': {'name': 'Plant a Tree', 'points': 50, 'category': 'Environmental'},
    'recycle': {'name': 'Recycle Items', 'points': 10, 'category': 'Waste Management'},
    'public_transport': {'name': 'Use Public Transport', 'points': 15, 'category': 'Transportation'},
    'reduce_plastic': {'name': 'Reduce Plastic Use', 'points': 20, 'category': 'Waste Management'},
    'energy_saving': {'name': 'Save Energy (LED, Turn off lights)', 'points': 25, 'category': 'Energy'},
    'water_conservation': {'name': 'Conserve Water', 'points': 15, 'category': 'Water'},
    'bike_walk': {'name': 'Walk or Bike Instead of Driving', 'points': 30, 'category': 'Transportation'},
    'composting': {'name': 'Composting', 'points': 35, 'category': 'Waste Management'},
    'local_shopping': {'name': 'Buy Local Products', 'points': 20, 'category': 'Consumption'},
    'renewable_energy': {'name': 'Use Renewable Energy', 'points': 40, 'category': 'Energy'}
}

BADGES = {
    'eco_starter': {'name': 'Eco Starter', 'requirement': 100, 'description': 'Earned 100 points'},
    'green_warrior': {'name': 'Green Warrior', 'requirement': 500, 'description': 'Earned 500 points'},
    'planet_protector': {'name': 'Planet Protector', 'requirement': 1000, 'description': 'Earned 1000 points'},
    'sustainability_champion': {'name': 'Sustainability Champion', 'requirement': 2000,
                                'description': 'Earned 2000 points'},
    'tree_planter': {'name': 'Tree Planter', 'requirement': 10, 'description': 'Planted 10 trees',
                     'action_type': 'plant_tree'},
    'recycling_hero': {'name': 'Recycling Hero', 'requirement': 50, 'description': 'Recycled 50 times',
                       'action_type': 'recycle'}
}


def db_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not ensure_db_connection():
            flash('Database connection unavailable. Please try again later.', 'error')
            return render_template('error.html', message='Database connection unavailable'), 500
        return f(*args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def get_user_badges(user_id):
    if users is None or actions is None:
        return []
    try:
        user_actions = list(actions.find({'user_id': user_id}))
        total_points = sum(action.get('points', 0) for action in user_actions)
        earned_badges = []
        for badge_id, badge_info in BADGES.items():
            if 'action_type' in badge_info:
                action_count = sum(1 for action in user_actions if action['action_type'] == badge_info['action_type'])
                if action_count >= badge_info['requirement']:
                    earned_badges.append(badge_id)
            else:
                if total_points >= badge_info['requirement']:
                    earned_badges.append(badge_id)
        return earned_badges
    except Exception as e:
        logger.error(f"Error getting user badges: {e}")
        return []


@app.route('/')
def index():
    if not ensure_db_connection():
        return render_template('index.html', total_users=0, total_actions=0, total_points=0, recent_activities=[],
                               db_error=True)
    try:
        total_users = users.count_documents({})
        total_actions = actions.count_documents({})
        total_points = sum(action.get('points', 0) for action in actions.find())
        recent_activities = list(actions.find().sort('timestamp', -1).limit(5))
        for activity in recent_activities:
            user = users.find_one({'_id': ObjectId(activity['user_id'])})
            activity['username'] = user['username'] if user else 'Unknown'
            activity['action_name'] = SUSTAINABLE_ACTIONS.get(activity['action_type'], {}).get('name', 'Unknown Action')
        return render_template('index.html', total_users=total_users, total_actions=total_actions,
                               total_points=total_points, recent_activities=recent_activities)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        return render_template('index.html', total_users=0, total_actions=0, total_points=0, recent_activities=[],
                               db_error=True)


@app.route('/register', methods=['GET', 'POST'])
@db_required
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            if users.find_one({'email': email}):
                flash('Email already registered!', 'error')
                return render_template('register.html')
            if users.find_one({'username': username}):
                flash('Username already taken!', 'error')
                return render_template('register.html')
            hashed_password = generate_password_hash(password)
            users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'joined_date': datetime.now(),
                'total_points': 0
            })
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error in register route: {e}")
            flash('Registration failed. Please try again.', 'error')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@db_required
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
            user = users.find_one({'email': email})
            if user and check_password_hash(user['password'], password):
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password!', 'error')
        except Exception as e:
            logger.error(f"Error in login route: {e}")
            flash('Login failed. Please try again.', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
@db_required
def dashboard():
    try:
        user_id = session['user_id']
        user = users.find_one({'_id': ObjectId(user_id)})
        user_actions = list(actions.find({'user_id': user_id}).sort('timestamp', -1))
        total_points = sum(action.get('points', 0) for action in user_actions)
        total_actions_count = len(user_actions)
        earned_badges = get_user_badges(user_id)
        users.update_one({'_id': ObjectId(user_id)}, {'$set': {'total_points': total_points}})
        for action in user_actions:
            action['action_name'] = SUSTAINABLE_ACTIONS.get(action['action_type'], {}).get('name', 'Unknown Action')
        return render_template('dashboard.html', user=user, user_actions=user_actions, total_points=total_points,
                               total_actions_count=total_actions_count, earned_badges=earned_badges, badges=BADGES)
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}")
        flash('Error loading dashboard. Please try again.', 'error')
        return redirect(url_for('index'))


@app.route('/log_action', methods=['GET', 'POST'])
@login_required
@db_required
def log_action():
    if request.method == 'POST':
        try:
            action_type = request.form['action_type']
            description = request.form['description']
            user_id = session['user_id']
            if action_type in SUSTAINABLE_ACTIONS:
                actions.insert_one({
                    'user_id': user_id,
                    'action_type': action_type,
                    'description': description,
                    'points': SUSTAINABLE_ACTIONS[action_type]['points'],
                    'timestamp': datetime.now()
                })
                flash(f'Action logged successfully! You earned {SUSTAINABLE_ACTIONS[action_type]["points"]} points!',
                      'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid action type!', 'error')
        except Exception as e:
            logger.error(f"Error in log_action route: {e}")
            flash('Error logging action. Please try again.', 'error')
    return render_template('log_action.html', sustainable_actions=SUSTAINABLE_ACTIONS)


@app.route('/leaderboard')
@db_required
def leaderboard():
    try:
        top_users = list(users.find().sort('total_points', -1).limit(10))
        for user in top_users:
            user_actions = list(actions.find({'user_id': str(user['_id'])}))
            total_points = sum(action.get('points', 0) for action in user_actions)
            users.update_one({'_id': user['_id']}, {'$set': {'total_points': total_points}})
            user['total_points'] = total_points
            user['badges'] = get_user_badges(str(user['_id']))
        top_users.sort(key=lambda x: x['total_points'], reverse=True)
        return render_template('leaderboard.html', top_users=top_users, badges=BADGES)
    except Exception as e:
        logger.error(f"Error in leaderboard route: {e}")
        flash('Error loading leaderboard. Please try again.', 'error')
        return redirect(url_for('index'))


@app.route('/api/dashboard_data')
@login_required
@db_required
def dashboard_data():
    try:
        user_id = session['user_id']
        user_actions = list(actions.find({'user_id': user_id}))
        category_stats = {}
        for action in user_actions:
            category = SUSTAINABLE_ACTIONS.get(action['action_type'], {}).get('category', 'Other')
            category_stats[category] = category_stats.get(category, 0) + 1
        monthly_stats = {}
        six_months_ago = datetime.now() - timedelta(days=180)
        for action in user_actions:
            if action['timestamp'] >= six_months_ago:
                month_key = action['timestamp'].strftime('%Y-%m')
                monthly_stats[month_key] = monthly_stats.get(month_key, 0) + 1
        return jsonify({'category_stats': category_stats, 'monthly_stats': monthly_stats})
    except Exception as e:
        logger.error(f"Error in dashboard_data API: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500


@app.route('/health')
def health_check():
    health_status = {'status': 'healthy', 'database': 'disconnected', 'timestamp': datetime.now().isoformat()}
    if ensure_db_connection():
        try:
            users.count_documents({}, maxTimeMS=5000)
            health_status['database'] = 'connected'
            return jsonify(health_status)
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
            return jsonify(health_status), 500
    else:
        health_status['status'] = 'unhealthy'
        health_status['error'] = 'Database not initialized'
        return jsonify(health_status), 500


@app.route('/reconnect')
def reconnect_db():
    global db_available
    logger.info("Manual database reconnection requested")
    db_available = init_db()
    if db_available:
        return jsonify({'status': 'success', 'message': 'Database reconnected successfully'})
    else:
        return jsonify({'status': 'error', 'message': 'Database reconnection failed'}), 500


@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', message='Internal server error'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', message='Page not found'), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)