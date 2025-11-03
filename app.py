import os
from flask import Flask, render_template, request, redirect, flash, url_for, make_response, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from  tronpy import Tron
from werkzeug.utils import secure_filename
import datetime

app = Flask(__name__)
app.secret_key = "246810aeiou@A"
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///user.db'
# Silence a deprecation warning
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

# --- Configuration ---
# 1. UPLOAD FOLDER: Path must be inside 'static' for Flask to serve images.
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 2. Allowed Extensions Utility
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

MY_ADDR = "TBSCDxkM27ukLiz8Z6exnDC6yzzmftwVTv"
tron=Tron()
def verify_trx_payment(txid: str):
    """
    Verify TRX on-chain payment sent to your wallet.
    No minimum amount required.
    """
    try:
        tx = tron.get_transaction(txid)
        receipt = tron.get_transaction_info(txid)
    except Exception:
        return {"success": False, "message": "Transaction not found or pending"}

    # Must be SUCCESS in the blockchain
    status = receipt.get("receipt", {}).get("result", "").upper()
    if status != "SUCCESS":
        return {"success": False, "message": "Transaction not confirmed yet"}

    # Extract details
    contract = tx["raw_data"]["contract"][0]
    value = contract["parameter"]["value"]
    if contract["type"] != "TransferContract":
        return {"success": False, "message": "Not a TRX transfer"}


    # Convert to base58 address
    to_addr = tron.to_base58check_address(bytes.fromhex(value["to_address"]))

    if to_addr != MY_ADDR:
        return {"success": False, "message": "Transaction not sent to your address"}

    amount_trx = value["amount"] / 1_000_000  # just for info

    return {
        "success": True,
        "message": "Payment verified ✅",
        "amount": amount_trx
    }

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Database Models ---
trx_id="TBSCDxkM27ukLiz8Z6exnDC6yzzmftwVTv"
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(300), unique=False, nullable=False)
    balance = db.Column(db.Float, default=0.0) 

class Nft(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(300), nullable=False, unique=False)
    nft_name = db.Column(db.String(100), nullable=False, unique=False)
    # Stores the filename of the uploaded image
    upload = db.Column(db.String(100), nullable=False, unique=False) 

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    receiver = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)



# --- Common NFT Fetching Function ---

def get_all_nfts_for_display():
    """Fetches all NFTs from the DB and formats them for the templates."""
    nfts_from_db = Nft.query.all()
    images = []
    for nft in nfts_from_db:
        images.append({
            # Filename path is relative to the static folder: static/uploads/filename
            'filename': 'uploads/' + nft.upload, 
            'name': nft.nft_name,
            # Placeholder/Hardcoded price
            'price': '0.1 ETH' 
        })
    return images

# --- Routes ---

@app.route('/')
def index():
    images = get_all_nfts_for_display()
    return render_template("index.html", images=images)

@app.route("/home")
def home():
    # Redirect to the root index which loads all NFTs
    return redirect(url_for('index'))

@app.route("/withdraw")
def withdraw():
    flash("Please Communicate with Admin for Withdrawal")
    return redirect(url_for('dashboard'))



@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))

    admin_user = User.query.get(session["user_id"])
    if admin_user.email != "pennypalmer75@gmail.com":
        return redirect(url_for("login"))

    if request.method == "POST":
        action = request.form.get("action")
        user_id = request.form.get("user_id")
        target_user = User.query.get(user_id)

        # Admin sends message
        if action == "send_message":
            reply = request.form.get("admin_reply")
            if reply and reply.strip():
                new_msg = Chat(
                    sender="admin",
                    receiver=target_user.username,
                    message=reply.strip(),
                    timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                db.session.add(new_msg)
                db.session.commit()
            return redirect(url_for("admin"))

        # Balance update
        if action == "update_balance":
            balance = request.form.get("balance")
            nft_balance = request.form.get("nft_balance")

            if balance is not None:
                target_user.balance = balance
            if nft_balance is not None:
                target_user.nft_balance = nft_balance

            db.session.commit()
            return redirect(url_for("admin"))

    users = User.query.all()

    for u in users:
        u.messages = Chat.query.filter(
            (Chat.sender == u.username) | (Chat.receiver == u.username)
        ).order_by(Chat.id).all()

    return render_template("admin.html", users=users)


@app.route("/signup",methods=["GET","POST"])
def signup():
    if request.method =="POST":
        username=request.form['username']
        email=request.form['email']
        password=generate_password_hash(request.form["password"])
        existing_user=User.query.filter_by(username=username).first()
        existing_email=User.query.filter_by(email=email).first()
        
        if existing_email:
            flash("You have an account, proceed to login")
            return redirect(url_for('login'))
        elif existing_user:
            flash("This username is already in use")
            return redirect(url_for('signup'))
        else:
            new_user= User(username=username,email=email,password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("You are free to Login now")
            resp=make_response(redirect(url_for('login')))
            # Removed redundant session/cookie setting for simple login flow
            return resp

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()
    
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Welcome back!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password. Please try again.")
            return redirect(url_for('login'))

    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        return redirect(url_for('signup'))
        
    user = User.query.filter_by(id=session["user_id"]).first()
    balance=User.query.filter_by(id=session["user_id"]).first()
    images = get_all_nfts_for_display()

    return render_template("dashboard.html", images=images, name=user.username,balance=balance.balance)

@app.route('/mint')
def mint():
    # Ensure only logged-in users can access the minting page
    if "user_id" not in session:
        flash("Please log in to mint an NFT.")
        return redirect(url_for('login'))
    return render_template('mint.html')

@app.route("/upload", methods=["GET","POST"])
def upload():
    if "user_id" not in session:
        flash("Please log in to mint an NFT.")
        return redirect(url_for('login'))
        
    if request.method == "POST":
        # 1. Retrieve data
        description = request.form.get("description")
        nft_name = request.form.get("nft_name")
        file = request.files.get("file") # Correctly retrieves FileStorage object
        transaction_id=request.form.get("transaction_id")
        
        # NOTE: Ignoring 'transaction_id' for simplicity, but you can retrieve it here.

        # 2. Validation
        if not description or not nft_name or not file or file.filename == '':
            flash("All fields and a file are required.")
            return redirect(url_for('mint'))
        if transaction_id =="":
            flash("The Transactio id is needed")
            return redirect(url_for("mint"))
        txid = transaction_id
        result = verify_trx_payment(txid)

        if result["success"]:
             flash("Go ahead to upload your NFT")
        else:
            flash("Verification failed")
            return redirect(url_for('mint'))

        # 3. File Processing and Saving (Fixes NameError, TypeError, and OSError)
        if file and allowed_file(file.filename): # Correct syntax: 'if file AND allowed_file()'
            filename = secure_filename(file.filename)
            # 🌟 Use UPLOAD_FOLDER for the correct path construction (Fixes OSError)
            save_path = os.path.join(UPLOAD_FOLDER, filename) 
            file.save(save_path)

            # 4. Save metadata to the Nft database model
            new_nft = Nft(
                description=description,
                nft_name=nft_name,
                upload=filename 
            )
            db.session.add(new_nft)
            db.session.commit()
        
            flash(f"NFT '{nft_name}' minted and listed successfully!")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Only PNG, JPG, and GIF are allowed.')
            return redirect(url_for('mint'))
    
    # If a GET request comes to /upload (should be handled by /mint usually)
    return redirect(url_for('mint')) 

@app.route('/chat', methods=["GET", "POST"])
def chat():
    if "user_id" not in session:
        return redirect(url_for('login'))

    user = User.query.get(session["user_id"])
    admin_username = "admin"

    if request.method == "POST":
        message_text = request.form.get("message")

        if message_text and message_text.strip():
            new_message = Chat(
                sender=user.username,
                receiver=admin_username,
                message=message_text.strip(),
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            db.session.add(new_message)
            db.session.commit()
            return redirect(url_for('chat'))

    messages = Chat.query.filter(
        ((Chat.sender == user.username) & (Chat.receiver == admin_username)) |
        ((Chat.sender == admin_username) & (Chat.receiver == user.username))
    ).order_by(Chat.timestamp.asc()).all()

    return render_template("messages.html", name=user.username, messages=messages)



@app.route('/logout')
def logout():
    session.pop("user_id", None)
    return redirect('/login')

if __name__=="__main__":
    with app.app_context():
        # db.create_all() MUST run to ensure the DB schema is correct (Fixes OperationalError)
        db.create_all()
    app.run(debug=True)