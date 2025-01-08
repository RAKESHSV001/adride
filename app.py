from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

class AdRideApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///adrides.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.app.config['SECRET_KEY'] = 'your_secret_key_here'

        self.db = SQLAlchemy(self.app)

        self.init_models()
        self.init_routes()

    def init_models(self):
        class User(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            name = self.db.Column(self.db.String(80), nullable=False)
            email = self.db.Column(self.db.String(120), unique=True, nullable=False)
            password_hash = self.db.Column(self.db.String(128), nullable=False)
            role = self.db.Column(self.db.String(20), nullable=False)  # 'wall_owner', 'advertiser', 'rickshaw_operator'

        class Campaign(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            title = self.db.Column(self.db.String(150), nullable=False)
            description = self.db.Column(self.db.Text, nullable=False)
            owner_id = self.db.Column(self.db.Integer, self.db.ForeignKey('user.id'), nullable=False)
            budget = self.db.Column(self.db.Float, nullable=False)
            status = self.db.Column(self.db.String(20), default='pending')  # 'pending', 'active', 'completed'

        class CampaignAssignment(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            campaign_id = self.db.Column(self.db.Integer, self.db.ForeignKey('campaign.id'), nullable=False)
            assignee_id = self.db.Column(self.db.Integer, self.db.ForeignKey('user.id'), nullable=False)
            status = self.db.Column(self.db.String(20), default='assigned')  # 'assigned', 'in-progress', 'completed'

        class Notification(self.db.Model):
            id = self.db.Column(self.db.Integer, primary_key=True)
            user_id = self.db.Column(self.db.Integer, self.db.ForeignKey('user.id'), nullable=False)
            message = self.db.Column(self.db.Text, nullable=False)
            is_read = self.db.Column(self.db.Boolean, default=False)

        self.User = User
        self.Campaign = Campaign
        self.CampaignAssignment = CampaignAssignment
        self.Notification = Notification

        with self.app.app_context():
            self.db.create_all()

    def init_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')

        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            if request.method == 'POST':
                name = request.form['name']
                email = request.form['email']
                password = request.form['password']
                role = request.form['role']
                password_hash = generate_password_hash(password)

                new_user = self.User(name=name, email=email, password_hash=password_hash, role=role)
                self.db.session.add(new_user)
                self.db.session.commit()
                return redirect(url_for('login'))

            return render_template('register.html')

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                email = request.form['email']
                password = request.form['password']
                user = self.User.query.filter_by(email=email).first()

                if user and check_password_hash(user.password_hash, password):
                    session['user_id'] = user.id
                    session['role'] = user.role
                    return redirect(url_for('dashboard'))

                return 'Invalid credentials', 401

            return render_template('login.html')

        @self.app.route('/logout')
        def logout():
            session.clear()
            return redirect(url_for('index'))

        @self.app.route('/dashboard')
        def dashboard():
            if 'user_id' in session:
                user = self.User.query.get(session['user_id'])
                return render_template('dashboard.html', user=user)
            return redirect(url_for('login'))

        @self.app.route('/signup', methods=['POST'])
        def signup():
            data = request.json
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            password_hash = generate_password_hash(password)

            if self.User.query.filter_by(email=email).first():
                return jsonify({"message": "Email already registered!"}), 400

            new_user = self.User(name=name, email=email, password_hash=password_hash, role='user')
            self.db.session.add(new_user)
            self.db.session.commit()

            return jsonify({"message": "Sign-Up Successful! Welcome to AdRide."})

        @self.app.route('/create_campaign', methods=['GET', 'POST'])
        def create_campaign():
            if 'user_id' in session:
                if request.method == 'POST':
                    title = request.form['title']
                    description = request.form['description']
                    budget = request.form['budget']

                    new_campaign = self.Campaign(
                        title=title, description=description, budget=budget, owner_id=session['user_id']
                    )
                    self.db.session.add(new_campaign)
                    self.db.session.commit()

                    return redirect(url_for('dashboard'))

                return render_template('create_campaign.html')

            return redirect(url_for('login'))

        @self.app.route('/assignments_overview')
        def assignments_overview():
            if 'role' in session and session['role'] == 'admin':
                assignments = (
                    self.CampaignAssignment.query
                    .join(self.Campaign, self.CampaignAssignment.campaign_id == self.Campaign.id)
                    .join(self.User, self.CampaignAssignment.assignee_id == self.User.id)
                    .add_columns(
                        self.Campaign.title,
                        self.User.name.label('assignee_name'),
                        self.CampaignAssignment.status
                    )
                    .all()
                )
                return render_template('assignments_overview.html', assignments=assignments)

            return jsonify({'message': 'Access denied.'}), 403

    def run(self):
        self.app.run(debug=True)

if __name__ == '__main__':
    app = AdRideApp()
    app.run()
