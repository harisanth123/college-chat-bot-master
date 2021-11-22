from enum import unique
from re import DEBUG
from flask import Flask, render_template,request,jsonify,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import model
from flask_sqlalchemy.model import Model
from flask_wtf import form
from flask_wtf.form import FlaskForm
from nltk import text
from werkzeug.utils import redirect
from werkzeug.wrappers import response
from wtforms.fields.numeric import IntegerField
from chat import get_response
from flask_wtf import FlaskForm
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY']='chatbot'
db = SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"password"})
    submit =SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("That user alrady exist's. please choose a different one")

class FeeEditForm(FlaskForm):
    fee_type = StringField(validators=[InputRequired()])
    value = IntegerField(validators=[InputRequired()])
    submit =SubmitField("Edit fee")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"password"})
    submit =SubmitField("Login")

@app.get("/")
def index_get():
    return render_template("base.html")

@app.post("/predict")
def predict():
    text = request.get_json().get("message")

    if 'credits'in text:
        if 'cgm'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'cgm'")
            result = [ row[0] for row in query_result]
            response = result[0]
            print(response)

        elif 'dsp'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'dsp'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'cd'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'cd'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'cn'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'cn'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'hci'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'hci'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'oomd'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'oomd'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'dsp'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'dsp'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'system lab'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'system lab'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'mini project'in text:
            query_result = db.engine.execute("select subject_credit from credits where subject_name  = 'mini project'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'total'in text:
            query_result = db.engine.execute("select SUM(subject_credit)from credits")
            result = [ row[0] for row in query_result]
            response = result[0]
    
        
        
    elif 'fee'in text:
        
        if 'hostel_fee'in text:
            query_result = db.engine.execute("select fee_amount from fee where fee_type = 'hostel_fee'")
            result = [ row[0] for row in query_result]
            response = result[0]
        

        elif 'college_fee'in text:
            query_result = db.engine.execute("select fee_amount from fee where fee_type = 'college_fee'")
            result = [ row[0] for row in query_result]
            response = result[0]
            print(response)

        
        elif 'canteen' in text:
            query_result = db.engine.execute("select fee_amount from fee where fee_type = 'canteen_fee'")
            result = [ row[0] for row in query_result]
            response = result[0]
            print(response)
        
        elif 'union' in text:
            query_result = db.engine.execute("select fee_amount from fee where fee_type = 'union fee'")
            result = [ row[0] for row in query_result]
            response = result[0]
        elif 'total' in text:
            query_result = db.engine.execute("select SUM(fee_amount)from fee")
            result = [ row[0] for row in query_result]
            response = result[0]
            print(response)
        elif 'first year fees' in text:
            query_result = db.engine.execute("select SUM(fee_amount)from fee")
            result = [ row[0] for row in query_result]
            response = result[0]
            print(response)
    
    elif 'subject'in text:
        dpt_result = db.engine.execute("select * from dpt")
        result = [ row[0] for row in dpt_result]
        response = result[0]
        query_result = db.engine.execute("select * from IT")
        result = [ row[0] for row in query_result]
        response = result[0]
        

        
    else: 
        response= get_response(text)      
    
    message={"answer":response}
    return jsonify(message)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['GET','POST'])
def register():
    form =RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template('register.html', form=form)
@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
@app.route('/editfee', methods=['GET','POST'])
@login_required
def editfee():
    form = FeeEditForm()
    if form.validate_on_submit():
        db.engine.execute("update fee set fee_amount="+form.value.data+"where fee_type="+form.fee_type.data)
        return redirect(url_for('dashboard'))
    return render_template('editfee.html',form=form)
    

if __name__=="__main__":
   app.run(debug=True)