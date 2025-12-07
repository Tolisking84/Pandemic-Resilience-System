from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
import jwt
import datetime
import os
import hashlib
from functools import wraps
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
import logging
from bson import ObjectId
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from io import BytesIO
import datetime
from datetime import datetime, timedelta
from datetime import timezone
from flask import make_response 
load_dotenv()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s:%(name)s: %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
DAY_RESTRICTIONS_ENABLED = False  # Set to False to enable day restrictions


# MongoDB setup
mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(mongo_uri)
db = client['pandemic_resilience']
user_collection = db['users']
merchant_collection = db['merchant_stocks']
vaccination_collection = db['vaccinations']
purchase_collection = db['purchases']
audit_log_collection = db['audit_log_collection']

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        token = None
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
        elif request.args.get('token'):
            token = request.args.get('token')
        else:
            logger.warning(f"No token provided in request to {request.path}")
            return jsonify({'message': 'Token is missing or invalid'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            logger.debug(f"Token decoded: {data}")
            current_user = user_collection.find_one({'email': data['email']})
            if not current_user:
                logger.warning(f"User not found for email: {data['email']}")
                return jsonify({'message': 'User not found'}), 401
            if current_user.get('status', 'active') == 'inactive':
                logger.warning(f"User is inactive: {data['email']}")
                return jsonify({'message': 'User account is inactive'}), 403
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return jsonify({'message': 'Invalid token'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def create_audit_log(action, user_id, details):
    audit_log = {
        'timestamp': datetime.utcnow(),
        'action': action,
        'user_id': user_id,
        'details': details
    }
    db.audit_logs.insert_one(audit_log)

@app.route('/allowed-purchase/<item_name>', methods=['GET'])
@token_required
def allowed_purchase(current_user, item_name):
    if current_user['role'] != 'public':
        return jsonify({'message': 'Unauthorized'}), 403

    today = datetime.utcnow().date()
    stock = 0
    limit = None
    merchant_data = db['merchant_stocks'].find()
    for merchant in merchant_data:
        for item in merchant.get('items', []):
            if item['name'].lower() == item_name.lower():
                stock = item.get('stock', 0)
                limit = item.get('limit', None)
                break

    if stock == 0:
        return jsonify({'allowed': 0}), 200
    if limit is None:
        return jsonify({'allowed': stock}), 200
    start_week = today - timedelta(days=today.weekday())
    pipeline = [
        {'$match': {
            'user_id': current_user['user_id'],
            'item_name': item_name,
            'date': {'$gte': start_week.isoformat()}
        }},
        {'$group': {
            '_id': None,
            'total': {'$sum': '$quantity'}
        }}
    ]
    agg = list(purchase_collection.aggregate(pipeline))
    bought = agg[0]['total'] if agg else 0

    remaining_limit = max(0, limit - bought)

    allowed = min(remaining_limit, stock)

    return jsonify({'allowed': allowed}), 200

@app.route('/can-purchase-today/<item_name>', methods=['GET'])
@token_required
def can_purchase_today(current_user, item_name):
    if not DAY_RESTRICTIONS_ENABLED:
        return jsonify({'can_purchase': True, 'message': 'Day restrictions are disabled. You can purchase anytime.'})

    dob = current_user.get('dob')
    if not dob:
        return jsonify({'can_purchase': False, 'message': 'Date of birth missing.'})

    try:
        birth_year = int(dob.split('-')[0])
        birth_digit = birth_year % 10
    except:
        return jsonify({'can_purchase': False, 'message': 'Invalid date of birth format.'})

    today = datetime.now().weekday()  # Monday = 0, Sunday = 6
    # Mapping of last digit to weekday
    digit_to_weekday = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 0, 8: 1, 9: 2}
    allowed_weekday = digit_to_weekday.get(birth_digit, 0)

    weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    if today != allowed_weekday:
        return jsonify({'can_purchase': False, 'message': f"You can only purchase on {weekday_names[allowed_weekday]}."})


    return jsonify({'can_purchase': True, 'message': 'Purchase allowed today.'})


@app.route('/purchase-item', methods=['POST'])
@token_required
def purchase_item(current_user):
    if current_user['role'] != 'public':
        logger.warning("Unauthorized: Only public users can purchase items")
        return jsonify({'message': 'Unauthorized'}), 403

    data = request.get_json() or {}
    item_name = data.get('item_name')
    qty = data.get('quantity')

    if not item_name or not isinstance(qty, int) or qty <= 0:
        logger.warning("Missing or invalid item_name/quantity")
        return jsonify({'message': 'Missing or invalid item_name/quantity'}), 400

    today = datetime.utcnow().date()
    current_weekday = today.weekday()

    if DAY_RESTRICTIONS_ENABLED and current_weekday >= 5:
        logger.warning(f"Purchase of {item_name} attempted on weekend by user {current_user['user_id']}")
        return jsonify({'message': 'Purchases are not allowed on weekends (Saturday or Sunday)'}), 403


    dob_year = int(current_user['dob'][:4])
    last_digit = dob_year % 10
    allowed_days = {
        (0, 2): 0,  # Monday
        (1, 3): 1,  # Tuesday
        (4, 5): 2,  # Wednesday
        (6, 7): 3,  # Thursday
        (8, 9): 4   # Friday
    }

    allowed_day = next(
        (day for digits, day in allowed_days.items() if last_digit in digits), None)

    if allowed_day is None:
        logger.warning("DOB year invalid for purchase rules")
        return jsonify({'message': 'DOB year invalid for purchase rules'}), 400

    if DAY_RESTRICTIONS_ENABLED and current_weekday != allowed_day:
        weekday_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        return jsonify({
            'message': f'You can only purchase on {weekday_names[allowed_day]}s'
        }), 403


    if item_name.lower() == 'mask':
        start_week = today - timedelta(days=today.weekday())
        pipeline = [
            {'$match': {
                'user_id': current_user['user_id'],
                'item_name': item_name,
                'date': {'$gte': start_week.isoformat()}
            }},
            {'$group': {
                '_id': None,
                'total': {'$sum': '$quantity'}
            }}
        ]

        agg = list(purchase_collection.aggregate(pipeline))
        bought = agg[0]['total'] if agg else 0

        if bought + qty > 7:
            logger.warning("Weekly mask limit exceeded")
            return jsonify({
                'message': 'Weekly limit exceeded. Max 7 masks per week allowed'
            }), 403

    # Check stock availability
    merchant_data = db['merchant_stocks'].find()
    stock_available = False
    for merchant in merchant_data:
        for item in merchant.get('items', []):
            if item['name'] == item_name and item['stock'] >= qty:
                item['stock'] -= qty
                db['merchant_stocks'].update_one(
                    {'merchant_id': merchant['merchant_id']},
                    {'$set': {'items': merchant['items']}}
                )
                stock_available = True
                break
        if stock_available:
            break

    if not stock_available:
        logger.warning(f"Insufficient stock for item {item_name}")
        return jsonify({'message': f'Insufficient stock for item {item_name}'}), 400

    purchase_collection.insert_one({
        'user_id': current_user['user_id'],
        'item_name': item_name,
        'quantity': qty,
        'date': today.isoformat()
    })

    create_audit_log(
        action='PURCHASE_ITEM',
        user_id=current_user['user_id'],
        details=f"Purchased {qty} of {item_name}"
    )

    logger.info(f"Purchase of {qty} {item_name} by user {current_user['user_id']} recorded successfully")
    return jsonify({'message': 'Purchase recorded successfully'}), 200

@app.route('/generate-receipt/<item_name>/<int:quantity>', methods=['GET'])
@token_required
def generate_receipt(current_user, item_name, quantity):
    if current_user['role'] != 'public':
        return jsonify({'message': 'Unauthorized'}), 403

    price_per_unit = 0
    total_amount = 0
    merchant_id = "Unknown Merchant"
    merchant_first_name = "N/A"
    merchant_last_name = "N/A"
    merchant_prs_id = "N/A"

    merchant_data = db['merchant_stocks'].find()
    found = False

    for merchant in merchant_data:
        for item in merchant.get('items', []):
            if item['name'] == item_name:
                price_per_unit = item.get('price', 0)
                merchant_id = merchant.get('merchant_id', 'Unknown Merchant')
                found = True
                break
        if found:
            break

    total_amount = price_per_unit * quantity

    merchant_user = user_collection.find_one({'merchant_id': merchant_id})
    if merchant_user:
        merchant_first_name = merchant_user.get('first_name', 'N/A')
        merchant_last_name = merchant_user.get('last_name', 'N/A')
        merchant_prs_id = merchant_user.get('prs_id', 'N/A')

    # --- PDF GENERATION ---
    

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle(f"Purchase Receipt - {item_name}")

    left_margin = 50
    right_margin = 545
    top_margin = 800
    bottom_margin = 50

    # Header
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawCentredString((left_margin + right_margin) / 2, top_margin, "Purchase Receipt")

    # Document details
    pdf.setFont("Helvetica", 12)
    y_position = top_margin - 40
    pdf.drawString(left_margin, y_position, f"Receipt ID: {item_name}-{quantity}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Issue Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y_position -= 30

    # Buyer details
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(left_margin, y_position, "Buyer Details")
    pdf.setFont("Helvetica", 12)
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Name: {current_user.get('first_name', 'N/A')} {current_user.get('last_name', 'N/A')}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"User ID: {current_user['user_id']}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"PRS ID: {current_user.get('prs_id', 'N/A')}")
    y_position -= 30

    # Merchant details
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(left_margin, y_position, "Merchant Details")
    pdf.setFont("Helvetica", 12)
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Name: {merchant_first_name} {merchant_last_name}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Merchant ID: {merchant_id}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"PRS ID: {merchant_prs_id}")
    y_position -= 30

    # Purchase details
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(left_margin, y_position, "Purchase Details")
    pdf.setFont("Helvetica", 12)
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Item: {item_name}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Quantity: {quantity}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Price per Unit: ${price_per_unit:.2f}")
    y_position -= 20
    pdf.drawString(left_margin, y_position, f"Total Amount: ${total_amount:.2f}")
    y_position -= 30

    # Footer
    pdf.setFont("Helvetica-Oblique", 10)
    pdf.drawCentredString((left_margin + right_margin) / 2, bottom_margin + 20, "Generated by Pandemic Resilience System")
    pdf.drawCentredString((left_margin + right_margin) / 2, bottom_margin, f"Contact: support@example.com | Issued on {datetime.now().strftime('%Y-%m-%d')}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=receipt_{item_name}_{quantity}.pdf'
    buffer.close()
    return response

@app.before_request
def before_request():
    if not request.is_secure and app.config['ENV'] != 'development':
        url = request.url.replace('http://', 'https://', 1)
        if request.host.split(':')[0] != 'localhost':
            port = app.config.get('HTTPS_PORT', 8443)
            if port != 443:
                host = request.host.split(':')[0]
                url = url.replace(f'{host}', f'{host}:{port}', 1)
        return redirect(url, code=301)
    
@app.route('/')
def index():
    logger.info("Root route accessed, rendering login")
    return render_template('login.html')

@app.route('/login', methods=['GET'])
def login_page():
    logger.info("Rendering login page")
    return render_template('login.html')

@app.route('/user-authentication', methods=['GET'])
def user_authentication_get():
    logger.warning("GET request to /user-authentication, redirecting to login")
    return redirect(url_for('login_page'))

@app.route('/user-authentication', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        email = data.get('email')
        password = data.get('password')
        logger.debug(f"Login attempt for email: {email}")
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not email or not password:
        logger.warning("Missing email or password")
        return jsonify({'message': 'Missing email or password'}), 400

    hashed_password = hash_password(password)
    user = user_collection.find_one({'email': email, 'password': hashed_password})
    if not user:
        logger.warning("Invalid credentials")
        return jsonify({'message': 'Invalid credentials'}), 401

    if user.get('status', 'active') == 'inactive':
        logger.warning("User is inactive")
        return jsonify({'message': 'User account is inactive'}), 403

    role = user['role']

    token = jwt.encode({
        'email': email,
        'role': role,
        'merchant_id': user.get('merchant_id'),
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    logger.info(f"User {email} logged in successfully, role: {role}")
    return jsonify({'token': token, 'role': role}), 200

def generate_next_user_id(role):
    prefix_map = {
        'public': 'U',
        'merchant': 'M',
        'government': 'GOV'
    }
    prefix = prefix_map.get(role)
    if not prefix:
        return None

    existing_ids = user_collection.find({'user_id': {'$regex': f'^{prefix}'}}, {'user_id': 1})
    used_numbers = set()

    for user in existing_ids:
        uid = user.get('user_id', '')
        if uid.startswith(prefix):
            number_part = uid.replace(prefix, '')
            try:
                used_numbers.add(int(number_part))
            except ValueError:
                continue

    next_number = 1
    while next_number in used_numbers:
        next_number += 1

    return f"{prefix}{next_number:03d}"

@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        dob = data.get('dob')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        user_id = generate_next_user_id(role)
        if not user_id:
            return jsonify({'message': 'Invalid role'}), 400
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    logger.debug(f"Registering user: {email}, role: {role}, user_id: {user_id}")

    if not first_name or not last_name or not dob or not email or not password or not role or not user_id:
        logger.warning("Missing required fields")
        return jsonify({'message': 'Missing required fields'}), 400

    if user_collection.find_one({'email': email}):
        logger.warning("Email already exists")
        return jsonify({'message': 'Email already exists'}), 400

    if user_collection.find_one({'user_id': user_id}):
        logger.warning("User ID already exists")
        return jsonify({'message': 'User ID already exists'}), 400

    # Hash the password
    hashed_password = hash_password(password)
    user_data = {
        'first_name': first_name,
        'last_name': last_name,
        'dob': dob,
        'email': email,
        'password': hashed_password,
        'role': role,
        'user_id': user_id,
        'status': 'active',
        'prs_id': f"{role.upper()[:3]}-{user_id}-{''.join(email.split('@')[0][-5:].upper())}"
    }

    if role == 'merchant':
        merchant_id = generate_next_user_id('merchant')
        user_data['merchant_id'] = merchant_id
        merchant_collection.insert_one({'merchant_id': merchant_id, 'items': []})

    user_collection.insert_one(user_data)
    logger.info(f"User {email} registered successfully with role {role}")
    return jsonify({'message': 'User registered successfully', 'prs_id': user_data['prs_id']}), 201

@app.route('/register', methods=['GET'])
def register_page():
    logger.info("Rendering register page")
    return render_template('register.html')

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    logger.info(f"User {current_user['email']} logged out successfully")
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/public')
@token_required
def public_dashboard(current_user):
    if current_user['role'] != 'public': 
        logger.warning("Unauthorized access to public dashboard")
        return jsonify({'message': 'Unauthorized'}), 403
    return render_template('public.html')

@app.route('/merchant')
@token_required
def merchant_dashboard(current_user):
    if current_user['role'] != 'merchant':
        logger.warning("Unauthorized access to merchant dashboard")
        return jsonify({'message': 'Unauthorized'}), 403
    return render_template('merchant.html')

@app.route('/admin')
@token_required
def government_dashboard(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized access to government dashboard")
        return jsonify({'message': 'Unauthorized'}), 403
    return render_template('admin.html')

@app.route('/merchant-sales', methods=['GET'])
@token_required
def merchant_sales(current_user):
    if current_user['role'] != 'merchant':
        return jsonify({'message': 'Unauthorized'}), 403

    merchant_id = current_user.get('merchant_id')
    if not merchant_id:
        return jsonify({'message': 'Merchant ID missing'}), 400

    merchant = merchant_collection.find_one({'merchant_id': merchant_id})
    if not merchant:
        return jsonify({'message': 'Merchant not found'}), 404

    item_names = [item['name'] for item in merchant.get('items', [])]

    sales = list(purchase_collection.find({'item_name': {'$in': item_names}}))

    for sale in sales:
        sale['_id'] = str(sale['_id'])
        buyer = user_collection.find_one({'user_id': sale['user_id']})
        sale['buyer_name'] = f"{buyer.get('first_name', 'N/A')} {buyer.get('last_name', 'N/A')}" if buyer else "Unknown"

    return jsonify({'sales': sales}), 200


@app.route('/user-inventory', methods=['GET'])
@token_required
def get_user_inventory(current_user):
    logger.debug(f"Fetching inventory for user: {current_user['email']}")
    role = current_user['role']
    response_data = {
        'role': role,
        'prs_id': current_user.get('prs_id', 'N/A'),
        'first_name': current_user.get('first_name', 'N/A'),
        'last_name': current_user.get('last_name', 'N/A'),
        'email': current_user.get('email', 'N/A'),
        'user_id': current_user.get('user_id', 'N/A'),
        'dob': current_user.get('dob', 'N/A'),
        'status': current_user.get('status', 'N/A').capitalize()
    }


    if role == 'merchant':
        merchant_id = current_user.get('merchant_id')
        if not merchant_id:
            logger.warning("Merchant ID not found for merchant user")
            return jsonify({'message': 'Merchant ID not found'}), 400

        merchant = merchant_collection.find_one({'merchant_id': merchant_id})
        if not merchant:
            logger.warning("Merchant not found in merchant_stocks")
            return jsonify({'message': 'Merchant not found'}), 404

        # Convert ObjectId to string for merchant items
        response_data['items'] = merchant.get('items', [])
        if not response_data['items']:
            response_data['message'] = 'No inventory found'

    # Fetch vaccination records
    vaccination = vaccination_collection.find_one({'user_id': current_user['user_id']})
    if vaccination:
        vaccination['_id'] = str(vaccination['_id'])
        vaccination['request_id'] = str(vaccination.get('request_id', vaccination['_id']))
    response_data['vaccination'] = vaccination

    # Fetch PDF records
    pdf = db['pdfs'].find_one({'user_id': current_user['user_id']})
    if pdf:
        pdf['_id'] = str(pdf['_id'])
        pdf['pdf_id'] = str(pdf.get('pdf_id', pdf['_id']))
    response_data['pdf'] = pdf

    return jsonify(response_data), 200

@app.route('/user-purchases', methods=['GET'])
@token_required
def user_purchases(current_user):
    if current_user['role'] != 'public':
        return jsonify({'message': 'Unauthorized'}), 403

    purchases = list(purchase_collection.find({'user_id': current_user['user_id']}))
    for p in purchases:
        p['_id'] = str(p['_id'])
    return jsonify({'purchases': purchases}), 200

@app.route('/upload-vaccination-pdf', methods=['POST'])
@token_required
def upload_vaccination_pdf(current_user):
    if 'file' not in request.files:
        logger.warning("No file part in request")
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        logger.warning("No file selected")
        return jsonify({'message': 'No file selected'}), 400

    if not allowed_file(file.filename):
        logger.warning("Invalid file type")
        return jsonify({'message': 'Invalid file type, only PDFs are allowed'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    pdf_data = {
        'user_id': current_user['user_id'],
        'filename': filename,
        'path': file_path,
        'upload_date': datetime.utcnow()
    }
    pdf_id = db['pdfs'].insert_one(pdf_data).inserted_id

    pdf_data['pdf_id'] = str(pdf_id)
    logger.info(f"PDF uploaded for user {current_user['user_id']}: {filename}")
    return jsonify({'message': 'PDF uploaded successfully', 'pdf_id': str(pdf_id)}), 200

@app.route('/generate-vaccination-pdf/<request_id>', methods=['GET'])
@token_required
def generate_vaccination_pdf(current_user, request_id):
    logger.debug(f"Starting PDF generation for request_id: {request_id}, user_id: {current_user['user_id']}")
    
    try:
        # Validate request_id
        logger.debug(f"Validating request_id: {request_id}")
        if not ObjectId.is_valid(request_id):
            logger.warning(f"Invalid request_id format: {request_id}")
            return jsonify({'message': 'Invalid request ID format'}), 400

        # Fetch vaccination request
        logger.debug(f"Querying vaccination_collection for request_id: {request_id}, user_id: {current_user['user_id']}")
        request = vaccination_collection.find_one({
            'request_id': request_id,
            'user_id': current_user['user_id']
        })
        if not request:
            logger.warning(f"No vaccination request found for request_id: {request_id}, user_id: {current_user['user_id']}")
            return jsonify({'message': 'Vaccination request not found or unauthorized'}), 404

        logger.debug(f"Vaccination request found: {request}")

        # Fetch user details
        logger.debug(f"Querying user_collection for user_id: {current_user['user_id']}")
        user = user_collection.find_one({'user_id': current_user['user_id']})
        if not user:
            logger.warning(f"No user found for user_id: {current_user['user_id']}")
            return jsonify({'message': 'User not found'}), 404

        logger.debug(f"User found: {user}")

        # Safely access fields
        request_data = {
            'vaccine_type': request.get('vaccine_type', 'N/A'),
            'status': request.get('status', 'N/A'),
            'date': request.get('date', 'N/A'),
            'admin_response': request.get('admin_response', 'N/A')
        }
        user_data = {
            'first_name': user.get('first_name', 'N/A'),
            'last_name': user.get('last_name', 'N/A'),
            'prs_id': user.get('prs_id', 'N/A')
        }

        logger.debug(f"Request data: {request_data}")
        logger.debug(f"User data: {user_data}")

        # Generate PDF
        logger.debug("Starting PDF generation")
        buffer = BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4) 
        pdf.setTitle(f"Vaccination Certificate - {request_id}")

        # Define margins
        left_margin = 50
        right_margin = 545
        top_margin = 800
        bottom_margin = 50

        # Header
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawCentredString((left_margin + right_margin) / 2, top_margin, "Vaccination Certificate")

        # Document details
        pdf.setFont("Helvetica", 12)
        y_position = top_margin - 40
        pdf.drawString(left_margin, y_position, f"Certificate ID: {request_id}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Issue Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y_position -= 30

        # User details
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(left_margin, y_position, "Recipient Details")
        pdf.setFont("Helvetica", 12)
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Name: {user_data['first_name']} {user_data['last_name']}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"User ID: {current_user['user_id']}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"PRS ID: {user_data['prs_id']}")
        y_position -= 30

        # Vaccination details
        pdf.setFont("Helvetica-Bold", 14)
        pdf.drawString(left_margin, y_position, "Vaccination Details")
        pdf.setFont("Helvetica", 12)
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Vaccine Type: {request_data['vaccine_type']}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Status: {request_data['status'].capitalize()}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Request Date: {request_data['date']}")
        y_position -= 20
        pdf.drawString(left_margin, y_position, f"Admin Response: {request_data['admin_response']}")
        y_position -= 30

        # Footer
        pdf.setFont("Helvetica-Oblique", 10)
        pdf.drawCentredString((left_margin + right_margin) / 2, bottom_margin + 20, "Generated by Pandemic Resilience System")
        pdf.drawCentredString((left_margin + right_margin) / 2, bottom_margin, f"Contact: support@example.com | Issued on {datetime.now().strftime('%Y-%m-%d')}")

        # Save PDF
        pdf.showPage()
        pdf.save()
        buffer.seek(0)
        logger.debug("PDF generated successfully")

        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=vaccination_certificate_{request_id}.pdf'
        buffer.close()

        logger.info(f"PDF generated and sent for request_id: {request_id}")
        return response

    except Exception as error:
        logger.error(f"Error generating PDF for request_id: {request_id}: {str(error)}", exc_info=True)
        return jsonify({'message': f'Error generating PDF: {str(error)}'}), 500

@app.route('/add-item', methods=['POST'])
@token_required
def add_item(current_user):
    logger.debug(f"Adding item for user: {current_user['email']}")
    if current_user['role'] != 'merchant':
        logger.warning("Unauthorized: Only merchants can add items")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        item_name = data.get('item_name')
        limit = data.get('limit') 
        stock = data.get('stock')
        price = data.get('price')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400
    
    if limit is not None and (not isinstance(limit, int) or limit < 1):
        return jsonify({'message': 'Limit must be a positive integer if provided'}), 400
    
    if not item_name or stock is None:
        logger.warning("Missing item name or stock")
        return jsonify({'message': 'Missing item name or stock'}), 400

    if not isinstance(stock, int) or stock < 0:
        logger.warning("Invalid stock value")
        return jsonify({'message': 'Stock must be a non-negative integer'}), 400

    if price is not None and (not isinstance(price, (int, float)) or price < 0):
        logger.warning("Invalid price value")
        return jsonify({'message': 'Price must be a non-negative number'}), 400

    merchant_id = current_user.get('merchant_id')
    merchant = merchant_collection.find_one({'merchant_id': merchant_id})
    if not merchant:
        logger.warning("Merchant not found")
        return jsonify({'message': 'Merchant not found'}), 404

    items = merchant.get('items', [])
    existing_item = next((item for item in items if item['name'] == item_name), None)
    if existing_item:
        logger.warning(f"Item {item_name} already exists")
        return jsonify({'message': f"Item {item_name} already exists"}), 400

    new_item = {'name': item_name, 'stock': stock}
    if price is not None:
        new_item['price'] = float(price)
    if limit is not None:
        new_item['limit'] = int(limit)

    items.append(new_item)
    merchant_collection.update_one(
        {'merchant_id': merchant_id},
        {'$set': {'items': items}}
    )

    create_audit_log(
        action='ADD_ITEM',
        user_id=current_user['user_id'],
        details=f"Added item {item_name} with stock {stock}"
    )

    logger.info(f"Item {item_name} added successfully")
    return jsonify({'message': 'Item added successfully'}), 200

@app.route('/update-stock', methods=['POST'])
@token_required
def update_stock(current_user):
    if current_user['role'] != 'merchant':
        logger.warning("Unauthorized: Only merchants can update stock")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        item_name = data.get('item_name')
        limit = data.get('limit')
        stock = data.get('stock')
        price = data.get('price')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400
    
    if limit is not None and (not isinstance(limit, int) or limit < 1):
        return jsonify({'message': 'Limit must be a positive integer if provided'}), 400

    if not item_name or stock is None:
        logger.warning("Missing item name or stock")
        return jsonify({'message': 'Missing item name or stock'}), 400

    if not isinstance(stock, int) or stock < 0:
        logger.warning("Invalid stock value")
        return jsonify({'message': 'Stock must be a non-negative integer'}), 400

    if price is not None and (not isinstance(price, (int, float)) or price < 0):
        logger.warning("Invalid price value")
        return jsonify({'message': 'Price must be a non-negative number'}), 400

    merchant_id = current_user.get('merchant_id')
    merchant = merchant_collection.find_one({'merchant_id': merchant_id})
    if not merchant:
        logger.warning("Merchant not found")
        return jsonify({'message': 'Merchant not found'}), 404

    items = merchant.get('items', [])
    item_to_update = next((item for item in items if item['name'] == item_name), None)
    if not item_to_update:
        logger.warning(f"Item {item_name} not found")
        return jsonify({'message': f"Item {item_name} not found"}), 404

    item_to_update['stock'] = stock
    if price is not None:
        item_to_update['price'] = float(price)
    if limit is not None:
        item_to_update['limit'] = int(limit)

    merchant_collection.update_one(
        {'merchant_id': merchant_id},
        {'$set': {'items': items}}
    )

    create_audit_log(
        action='UPDATE_STOCK',
        user_id=current_user['user_id'],
        details=f"Updated stock for {item_name} to {stock}"
    )

    logger.info(f"Stock updated for item {item_name} to {stock}, price: {price}")
    return jsonify({'message': 'Stock updated successfully'}), 200

@app.route('/remove-item', methods=['POST'])
@token_required
def remove_item(current_user):
    if current_user['role'] != 'merchant':
        logger.warning("Unauthorized: Only merchants can remove items")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        item_name = data.get('item_name')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not item_name:
        logger.warning("Missing item name")
        return jsonify({'message': 'Missing item name'}), 400

    merchant_id = current_user.get('merchant_id')
    merchant = merchant_collection.find_one({'merchant_id': merchant_id})
    if not merchant:
        logger.warning("Merchant not found")
        return jsonify({'message': 'Merchant not found'}), 404

    items = merchant.get('items', [])
    if not any(item['name'] == item_name for item in items):
        logger.warning(f"Item {item_name} not found")
        return jsonify({'message': f"Item {item_name} not found"}), 404

    items = [item for item in items if item['name'] != item_name]
    merchant_collection.update_one(
        {'merchant_id': merchant_id},
        {'$set': {'items': items}}
    )

    create_audit_log(
        action='REMOVE_ITEM',
        user_id=current_user['user_id'],
        details=f"Removed item {item_name}"
    )

    logger.info(f"Item {item_name} removed successfully")
    return jsonify({'message': 'Item removed successfully'}), 200

@app.route('/batch-update-stock', methods=['POST'])
@token_required
def batch_update_stock(current_user):
    if current_user['role'] != 'merchant':
        logger.warning("Unauthorized: Only merchants can batch update stock")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        items_to_update = data.get('items')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not items_to_update or not isinstance(items_to_update, list):
        logger.warning("Invalid or missing items list")
        return jsonify({'message': 'Invalid or missing items list'}), 400

    merchant_id = current_user.get('merchant_id')
    merchant = merchant_collection.find_one({'merchant_id': merchant_id})
    if not merchant:
        logger.warning("Merchant not found")
        return jsonify({'message': 'Merchant not found'}), 404

    current_items = merchant.get('items', [])
    for update_item in items_to_update:
        item_name = update_item.get('item_name')
        stock = update_item.get('stock')
        price = update_item.get('price')

        if not item_name or stock is None:
            logger.warning("Missing item name or stock in batch update")
            return jsonify({'message': 'Missing item name or stock'}), 400

        if not isinstance(stock, int) or stock < 0:
            logger.warning("Invalid stock value in batch update")
            return jsonify({'message': 'Stock must be a non-negative integer'}), 400

        if price is not None and (not isinstance(price, (int, float)) or price < 0):
            logger.warning("Invalid price value in batch update")
            return jsonify({'message': 'Price must be a non-negative number'}), 400

        item_to_update = next((item for item in current_items if item['name'] == item_name), None)
        if item_to_update:
            item_to_update['stock'] = stock
            if price is not None:
                item_to_update['price'] = float(price)
        else:
            new_item = {'name': item_name, 'stock': stock}
            if price is not None:
                new_item['price'] = float(price)
            current_items.append(new_item)

    merchant_collection.update_one(
        {'merchant_id': merchant_id},
        {'$set': {'items': current_items}}
    )

    create_audit_log(
        action='BATCH_UPDATE_STOCK',
        user_id=current_user['user_id'],
        details=f"Batch updated stock for {len(items_to_update)} items"
    )

    logger.info(f"Batch update completed for {len(items_to_update)} items")
    return jsonify({'message': 'Batch update successful'}), 200

@app.route('/search-items', methods=['POST'])
@token_required
def search_items(current_user):
    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        item_name = data.get('item_name')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not item_name:
        logger.warning("Missing item name for search")
        return jsonify({'message': 'Missing item name'}), 400

    merchants = merchant_collection.find()
    results = []
    for merchant in merchants:
        items = merchant.get('items', [])
        for item in items:
            if item_name.lower() in item['name'].lower():
                results.append({
                    'item_name': item['name'],
                    'stock': item['stock'],
                    'price': item.get('price'),
                    'merchant_id': merchant['merchant_id']
                })

    logger.info(f"Search for {item_name} returned {len(results)} results")
    return jsonify({'results': results}), 200

@app.route('/admin/create-user', methods=['POST'])
@token_required
def admin_create_user(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can create users")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        dob = data.get('dob')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not first_name or not last_name or not dob or not email or not password or not role:
        logger.warning("Missing required fields for user creation")
        return jsonify({'message': 'Missing required fields'}), 400

    if user_collection.find_one({'email': email}):
        logger.warning("Email already exists")
        return jsonify({'message': 'Email already exists'}), 400

    user_id = generate_next_user_id(role)
    if not user_id:
        logger.warning("Invalid role provided")
        return jsonify({'message': 'Invalid role'}), 400

    if user_collection.find_one({'user_id': user_id}):
        logger.warning("Generated user ID already exists")
        return jsonify({'message': 'Generated user ID already exists'}), 400

    # Hash the password
    hashed_password = hash_password(password)
    user_data = {
        'first_name': first_name,
        'last_name': last_name,
        'dob': dob,
        'email': email,
        'password': hashed_password,
        'role': role,
        'user_id': user_id,
        'status': 'active',
        'prs_id': f"{role.upper()[:3]}-{user_id}-{''.join(email.split('@')[0][-5:].upper())}"
    }

    if role == 'merchant':
        merchant_id = generate_next_user_id('merchant')
        user_data['merchant_id'] = merchant_id
        if merchant_collection.find_one({'merchant_id': merchant_id}):
            logger.warning("Generated merchant ID already exists")
            return jsonify({'message': 'Generated merchant ID already exists'}), 400
        merchant_collection.insert_one({'merchant_id': merchant_id, 'items': []})

    user_collection.insert_one(user_data)

    create_audit_log(
        action='CREATE_USER',
        user_id=current_user['user_id'],
        details=f"Created user with email {email} and role {role}"
    )

    logger.info(f"Government user created user {email} with role {role}")
    return jsonify({
        'message': 'User created successfully',
        'prs_id': user_data['prs_id']
    }), 201

@app.route('/admin/delete-user', methods=['POST'])
@token_required
def admin_delete_user(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can delete users")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        email = data.get('email')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not email:
        logger.warning("Missing email for user deletion")
        return jsonify({'message': 'Missing email'}), 400

    user = user_collection.find_one({'email': email})
    if not user:
        logger.warning("User not found for deletion")
        return jsonify({'message': 'User not found'}), 404

    if user['role'] == 'merchant':
        merchant_collection.delete_one({'merchant_id': user.get('merchant_id')})

    user_collection.delete_one({'email': email})

    create_audit_log(
        action='DELETE_USER',
        user_id=current_user['user_id'],
        details=f"Deleted user with email {email}"
    )

    logger.info(f"Government user deleted user {email}")
    return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/admin/list-users', methods=['GET'])
@token_required
def admin_list_users(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can list users")
        return jsonify({'message': 'Unauthorized'}), 403

    users = list(user_collection.find({}, {'password': 0}))
    for user in users:
        user['_id'] = str(user['_id'])
    logger.info(f"Government user listed {len(users)} users")
    return jsonify(users), 200

@app.route('/admin/add-vaccination', methods=['POST'])
@token_required
def admin_add_vaccination(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can add vaccination records")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        user_id = data.get('user_id')
        status = data.get('status')
        date = data.get('date')
        vaccine_type = data.get('vaccine_type')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not user_id or not status or not date or not vaccine_type:
        logger.warning("Missing required fields for vaccination record")
        return jsonify({'message': 'Missing required fields'}), 400

    user = user_collection.find_one({'user_id': user_id})
    if not user:
        logger.warning("User not found for vaccination record")
        return jsonify({'message': 'User not found'}), 404

    vaccination_data = {
        'user_id': user_id,
        'status': status,
        'date': date,
        'vaccine_type': vaccine_type
    }

    vaccination_collection.update_one(
        {'user_id': user_id},
        {'$set': vaccination_data},
        upsert=True
    )

    create_audit_log(
        action='ADD_VACCINATION',
        user_id=current_user['user_id'],
        details=f"Added vaccination record for user {user_id} with vaccine {vaccine_type}"
    )

    logger.info(f"Government user added vaccination record for user {user_id}")
    return jsonify({'message': 'Vaccination record added successfully'}), 200

@app.route('/admin/list-stocks')
@token_required
def list_stocks(current_user):
    if current_user['role'] not in ['government', 'merchant', 'public']:
        return jsonify({"message": "Forbidden"}), 403

    stocks = merchant_collection.find()
    all_data = []

    for merchant in stocks:
        merchant_id = merchant.get("merchant_id", "N/A")
        items = merchant.get("items", [])

        user = user_collection.find_one({'merchant_id': merchant_id})
        first_name = user.get("first_name", "Missing Account") if user else "Missing Account"
        last_name = user.get("last_name", "") if user else ""
        email = user.get("email", "Missing")

        all_data.append({
            "merchant_id": merchant_id,
            "merchant_name": f"{first_name} {last_name}",
            "merchant_email": email,
            "items": items
        })

    return jsonify(all_data), 200



@app.route('/admin/statistics', methods=['GET'])
@token_required
def admin_statistics(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized access to government statistics")
        return jsonify({'message': 'Unauthorized'}), 403

    total_users = user_collection.count_documents({'role': 'public'})
    total_merchants = user_collection.count_documents({'role': 'merchant'})
    total_admins = user_collection.count_documents({'role': 'government'})
    total_vaccinated = vaccination_collection.count_documents({
    'status': {'$regex': '^Approved$', '$options': 'i'}  # Match 'Approved' case-insensitively
    })
    # Use total_users (public users) as the denominator
    vaccination_rate = (total_vaccinated / total_users * 100) if total_users > 0 else 0

    stats = {
        'users': total_users,
        'merchants': total_merchants,
        'admins': total_admins,
        'vaccination_rate': round(vaccination_rate, 2)  # Round to 2 decimal places
    }

    logger.info(f"Government statistics: {stats}")
    return jsonify(stats), 200

@app.route('/admin/toggle-user-status', methods=['POST'])
@token_required
def toggle_user_status(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can toggle user status")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        email = data.get('email')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not email:
        logger.warning("Missing email for toggling user status")
        return jsonify({'message': 'Missing email'}), 400

    user = user_collection.find_one({'email': email})
    if not user:
        logger.warning("User not found for toggling status")
        return jsonify({'message': 'User not found'}), 404

    new_status = 'inactive' if user.get('status', 'active') == 'active' else 'active'
    user_collection.update_one(
        {'email': email},
        {'$set': {'status': new_status}}
    )

    create_audit_log(
        action='TOGGLE_USER_STATUS',
        user_id=current_user['user_id'],
        details=f"Toggled user status for {email} to {new_status}"
    )

    logger.info(f"Government user toggled user {email} status to {new_status}")
    return jsonify({'message': f"User status toggled to {new_status}"}), 200

@app.route('/admin/search-users', methods=['POST'])
@token_required
def search_users(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can search users")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        query = data.get('query', '').strip()
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not query:
        logger.info("Empty query, returning empty list")
        return jsonify([]), 200

    # Search across first_name, last_name, email, user_id, and prs_id (case-insensitive)
    users = list(user_collection.find(
        {
            '$or': [
                {'first_name': {'$regex': query, '$options': 'i'}},
                {'last_name': {'$regex': query, '$options': 'i'}},
                {'email': {'$regex': query, '$options': 'i'}},
                {'user_id': {'$regex': query, '$options': 'i'}},
                {'prs_id': {'$regex': query, '$options': 'i'}}
            ]
        },
        {'password': 0}  # Exclude password field
    ))

    for user in users:
        user['_id'] = str(user['_id'])

    logger.info(f"Government search returned {len(users)} users for query: {query}")
    return jsonify(users), 200

@app.route('/request-vaccination', methods=['POST'])
@token_required
def request_vaccination(current_user):
    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        vaccine_type = data.get('vaccine_type')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not vaccine_type:
        logger.warning("Missing vaccine type for request")
        return jsonify({'message': 'Missing vaccine type'}), 400

    # Check the number of pending requests for the user
    pending_requests = vaccination_collection.count_documents({
        'user_id': current_user['user_id'],
        'status': 'Pending'
    })

    if pending_requests >= 3:
        logger.warning(f"User {current_user['user_id']} exceeded maximum pending requests")
        return jsonify({'message': 'You have reached the maximum of 3 pending vaccination requests. Please wait for admin review.'}), 403

    vaccination_data = {
        'user_id': current_user['user_id'],
        'status': 'Pending',
        'date': datetime.utcnow().strftime('%Y-%m-%d'),
        'vaccine_type': vaccine_type,
        'admin_response': '',
        'request_id': str(ObjectId())
    }

    vaccination_collection.update_one(
        {'user_id': current_user['user_id'], 'vaccine_type': vaccine_type, 'status': 'Pending'},
        {'$set': vaccination_data},
        upsert=True
    )

    create_audit_log(
        action='REQUEST_VACCINATION',
        user_id=current_user['user_id'],
        details=f"Requested vaccination: {vaccine_type}"
    )

    logger.info(f"User {current_user['user_id']} requested vaccination: {vaccine_type}")
    return jsonify({'message': 'Vaccination request submitted successfully'}), 200

@app.route('/admin/list-vaccination-requests', methods=['GET'])
@token_required
def admin_list_vaccination_requests(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can list vaccination requests")
        return jsonify({'message': 'Unauthorized'}), 403

    # Fetch all pending vaccination requests
    requests = list(vaccination_collection.find({'status': 'Pending'}))
    for req in requests:
        req['_id'] = str(req['_id'])
        req['request_id'] = req.get('request_id', str(req['_id']))

    logger.info(f"Government user listed {len(requests)} vaccination requests")
    return jsonify(requests), 200

@app.route('/admin/approve-vaccination', methods=['POST'])
@token_required
def admin_approve_vaccination(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can approve vaccination requests")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        request_id = data.get('request_id')
        admin_response = data.get('admin_response', '')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not request_id:
        logger.warning("Missing request ID")
        return jsonify({'message': 'Missing request ID'}), 400

    request_data = vaccination_collection.find_one({'request_id': request_id, 'status': 'Pending'})
    if not request_data:
        logger.warning("Vaccination request not found or already processed")
        return jsonify({'message': 'Vaccination request not found or already processed'}), 404
    if not admin_response:
        admin_response = f"Approved by admin on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    vaccination_collection.update_one(
        {'request_id': request_id},
        {'$set': {'status': 'Approved', 'admin_response': admin_response}}
    )

    create_audit_log(
        action='APPROVE_VACCINATION',
        user_id=current_user['user_id'],
        details=f"Approved vaccination request {request_id} with response: {admin_response}"
    )

    logger.info(f"Government user approved vaccination request {request_id}")
    return jsonify({'message': 'Vaccination request approved successfully'}), 200

@app.route('/admin/reject-vaccination', methods=['POST'])
@token_required
def admin_reject_vaccination(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can reject vaccination requests")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        request_id = data.get('request_id')
        admin_response = data.get('admin_response', '')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not request_id:
        logger.warning("Missing request ID")
        return jsonify({'message': 'Missing request ID'}), 400

    request_data = vaccination_collection.find_one({'request_id': request_id, 'status': 'Pending'})
    if not request_data:
        logger.warning("Vaccination request not found or already processed")
        return jsonify({'message': 'Vaccination request not found or already processed'}), 404

    if not admin_response:
        admin_response = f"Rejected by admin on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    vaccination_collection.update_one(
        {'request_id': request_id},
        {'$set': {'status': 'Rejected', 'admin_response': admin_response}}
    )

    create_audit_log(
        action='REJECT_VACCINATION',
        user_id=current_user['user_id'],
        details=f"Rejected vaccination request {request_id} with response: {admin_response}"
    )

    logger.info(f"Government user rejected vaccination request {request_id}")
    return jsonify({'message': 'Vaccination request rejected successfully'}), 200

@app.route('/public/vaccination-request-status', methods=['GET'])
@token_required
def public_vaccination_request_status(current_user):
    if current_user['role'] != 'public':
        logger.warning("Unauthorized: Only public users can view their vaccination request status")
        return jsonify({'message': 'Unauthorized'}), 403

    requests = list(vaccination_collection.find({'user_id': current_user['user_id']}))
    for req in requests:
        req['_id'] = str(req['_id'])
        req['request_id'] = req.get('request_id', str(req['_id']))

    logger.info(f"Public user {current_user['user_id']} viewed their vaccination request status")
    return jsonify(requests), 200

@app.route('/public/clear-vaccination-requests', methods=['POST'])
@token_required
def clear_vaccination_requests(current_user):
    if current_user['role'] != 'public':
        logger.warning("Unauthorized: Only public users can clear their vaccination requests")
        return jsonify({'message': 'Unauthorized'}), 403

    result = vaccination_collection.delete_many({
        'user_id': current_user['user_id'],
        'status': 'Pending'
    })

    logger.info(f"Public user {current_user['user_id']} cleared {result.deleted_count} pending vaccination requests")
    return jsonify({'message': f'{result.deleted_count} pending vaccination request(s) cleared successfully'}), 200

@app.route('/public/latest-approved-vaccine', methods=['GET'])
@token_required
def get_latest_approved_vaccine(current_user):
    if current_user['role'] != 'public':
        logger.warning("Unauthorized: Only public users can view their latest approved vaccine")
        return jsonify({'message': 'Unauthorized'}), 403

    # Fetch the latest approved vaccination request for the user
    latest_vaccine = vaccination_collection.find_one(
        {'user_id': current_user['user_id'], 'status': 'Approved'},
        sort=[('date', -1)]  # Sort by date descending to get the most recent
    )

    if not latest_vaccine:
        logger.info(f"No approved vaccines found for user {current_user['user_id']}")
        return jsonify({'message': 'No approved vaccines found'}), 200

    latest_vaccine['_id'] = str(latest_vaccine['_id'])
    latest_vaccine['request_id'] = latest_vaccine.get('request_id', str(latest_vaccine['_id']))

    logger.info(f"Public user {current_user['user_id']} retrieved latest approved vaccine")
    return jsonify(latest_vaccine), 200

@app.route('/admin/list-all-vaccination-requests', methods=['GET'])
@token_required
def admin_list_all_vaccination_requests(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can list all vaccination requests")
        return jsonify({'message': 'Unauthorized'}), 403

    # Fetch all vaccination requests
    requests = list(vaccination_collection.find({}))
    # Fetch user data for each request
    result = []
    for req in requests:
        user = user_collection.find_one({'user_id': req['user_id']}, {'first_name': 1, 'last_name': 1, '_id': 0})
        req['_id'] = str(req['_id'])
        req['request_id'] = req.get('request_id', str(req['_id']))
        req['first_name'] = user.get('first_name', '') if user else ''
        req['last_name'] = user.get('last_name', '') if user else ''
        result.append(req)

    logger.info(f"Government user listed {len(requests)} vaccination requests")
    return jsonify(result), 200

@app.route('/admin/update-vaccination-status', methods=['POST'])
@token_required
def admin_update_vaccination_status(current_user):
    if current_user['role'] != 'government':
        logger.warning("Unauthorized: Only government users can update vaccination request status")
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        data = request.get_json()
        if not data:
            logger.warning("No JSON payload provided")
            return jsonify({'message': 'Invalid request format'}), 400
        request_id = data.get('request_id')
        new_status = data.get('status')
        admin_response = data.get('admin_response', '')
    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({'message': 'Invalid request format'}), 400

    if not request_id or not new_status:
        logger.warning("Missing request ID or status")
        return jsonify({'message': 'Missing request ID or status'}), 400

    if new_status not in ['Pending', 'Approved', 'Rejected']:
        logger.warning("Invalid status provided")
        return jsonify({'message': 'Invalid status. Must be Pending, Approved, or Rejected'}), 400

    request_data = vaccination_collection.find_one({'request_id': request_id})
    if not request_data:
        logger.warning("Vaccination request not found")
        return jsonify({'message': 'Vaccination request not found'}), 404

    if not admin_response:
        admin_response = f"Status updated to {new_status} by admin on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    vaccination_collection.update_one(
        {'request_id': request_id},
        {'$set': {'status': new_status, 'admin_response': admin_response}}
    )

    create_audit_log(
        action='UPDATE_VACCINATION_STATUS',
        user_id=current_user['user_id'],
        details=f"Updated vaccination request {request_id} to {new_status} with response: {admin_response}"
    )

    logger.info(f"Government user updated vaccination request {request_id} to {new_status}")
    return jsonify({'message': f'Vaccination request status updated to {new_status}'}), 200

@app.route('/admin/audit-logs', methods=['GET'])
@token_required
def admin_audit_logs(current_user):
    if current_user['role'] != 'government':
        return jsonify({'message': 'Unauthorized'}), 403

    logs = list(db.audit_logs.find().sort("timestamp", -1).limit(200))
    for log in logs:
        log['_id'] = str(log['_id'])
        log['timestamp'] = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')

    return jsonify({'logs': logs}), 200

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    ssl_cert = os.getenv('SSL_CERT_PATH', 'path/to/cert.pem')
    ssl_key = os.getenv('SSL_KEY_PATH', 'path/to/privkey.pem')

    app.config['HTTPS_PORT'] = int(os.getenv('HTTPS_PORT', 8443))

    try:
        if not os.path.exists(ssl_cert) or not os.path.exists(ssl_key):
            raise FileNotFoundError("SSL certificate or key file not found")

        app.run(
            host='0.0.0.0',
            port=app.config['HTTPS_PORT'],
            ssl_context=(ssl_cert, ssl_key),
            debug=False
        )
    except FileNotFoundError as e:
        logger.error(f"SSL setup failed: {str(e)}")
        print("Error: SSL certificate or key file not found. Please set SSL_CERT_PATH and SSL_KEY_PATH in your .env file.")
        print("Falling back to HTTP mode on port 5000 for development...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except PermissionError as e:
        logger.error(f"Permission error: {str(e)}")
        print(f"Error: Cannot bind to port {app.config['HTTPS_PORT']}. Ports below 1024 require root privileges.")
        print("Falling back to HTTP mode on port 5000 for development...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        print(f"Error: Failed to start server with HTTPS: {str(e)}")
        print("Falling back to HTTP mode on port 5000 for development...")
        app.run(host='0.0.0.0', port=5000, debug=True)