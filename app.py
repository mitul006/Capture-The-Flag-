from flask import Flask, render_template, request, redirect, jsonify, render_template_string
import sqlite3
import os
import base64
import hashlib
import re as regex
import random
from urllib.parse import unquote
from selenium import webdriver
import requests as re
from urllib.parse import urlparse

app = Flask(__name__)

#Variables used in the app

@app.route('/')
def index():
     return render_template("index.html")

####################################################################################################################################
####################################################################################################################################
################################################## Authentication Bypass vuln ######################################################
####################################################################################################################################
####################################################################################################################################

@app.route('/challenge1/QXV0aGVudGljYXRpb25CeXBhc3M=',methods=['GET'])
def AuthBypass():
    if request.method=='GET':
        return render_template('AuthBypass.html')
    else:
        return "Method not permitted", 405

#REST based API for logging in challenge 1
@app.route('/challenge1/login',methods=['POST'])
def challenge1_login():
    if(request.method=='POST'):

        #Fetching user credential data from the request
        uname = request.form['uname']
        pwd = request.form['pwd']

        #Using sqlite3 to connect to DB and query the users table
        BASE_PATH = os.getcwd()
        db=sqlite3.connect(BASE_PATH+'/challenge1_db.db')
        cursor=db.cursor()
        
        #Using parameterized query to prevent SQL Injection
        cursor.execute('''select * from users where username=? and password=?''',(uname,pwd))
        record=cursor.fetchall()
        print(record)

        #Validating the Login and sending the response in a json format
        if len(record)>0 and record[0][0]==uname and record[0][1]==pwd:
            #Creating a login cookie that has encoded and hashed user information
            login_cookie=str(str(base64.b64encode(uname.encode()).decode("ascii"))+"."+str(hashlib.md5(pwd.encode()).hexdigest()))
            print(login_cookie)

            #Setting the login flag as True indicating that user has logged in successfully
            cursor.execute('''update users set logged_in=? where username=?''',('True',uname))
            db.commit()

            response_dict={'status':200,'auth':'validated','user':uname,'login_cookie':login_cookie}
            return jsonify(response_dict)
        else:
            #Creating a login cookie that has encoded and hashed user information
            login_cookie=str(str(base64.b64encode(uname.encode()).decode("ascii"))+'.'+str(hashlib.md5(pwd.encode()).hexdigest()))
            response_dict={'status':401,'user':uname,'auth':'unvalidated','error':'User not validated','login_cookie':login_cookie}
            return jsonify(response_dict), 401
    
    #Not permitting any other methods like GET,TRACE,TRACK,HEAD and OPTIONS and hence preventing vulnerabilities associated with them
    else:
        return "Method not permitted", 405    

@app.route('/challenge1/user/dashboard/session/<string:session>',methods=['GET'])
def dashboard(session):
    user_session = session

    # Sample session string YWRtaW4=.be28e2a770fbba318f66ad842f5a7f2b
    user_logged_in_encoded = user_session.split('.')[0]

    #Decoding the base64 format
    user_logged_in_decoded = str(base64.b64decode(user_logged_in_encoded.encode()).decode())
    print(user_logged_in_decoded)
    print(type(user_logged_in_decoded))

    #Using sqlite3 to connect to DB and query the users table
    BASE_PATH = os.getcwd()
    db=sqlite3.connect(BASE_PATH+'/challenge1_db.db')
    cursor=db.cursor()

    #Setting the login flag for the user
    #This will set the logged in flag as true only if the user exists. Hence preventing IDOR for dashboard page
    cursor.execute('''update users set logged_in=? where username=?''',('True',user_logged_in_decoded))
    db.commit()

    #Now checking and selecting if the logged_in colum is set true for the user and then displaying the dashboard
    cursor.execute('''select logged_in from users where username=?''',(user_logged_in_decoded,))
    logged_in=cursor.fetchone()

    if logged_in!=None and logged_in[0]=='True':
        return render_template('Dashboard.html',username=user_logged_in_decoded,session=user_session), 200
    elif logged_in!=None and logged_in[0]=='False':
        return "<center> User not logged in! PLease login again to access the dashboard. <br><br><br> <a href='/challenge1/QXV0aGVudGljYXRpb25CeXBhc3M='>Login here</a></center>", 401
    else:
        return "<center><h1>Session tampering detected! This activity will be logged and reported.</h1> <br><br><br> <a href='/challenge1/QXV0aGVudGljYXRpb25CeXBhc3M='>Login here</a></center>", 401

#User logout function
@app.route('/challenge1/user/sesion/logout/<string:session>',methods=['GET'])
def logout(session):
    user_logged_in_encoded = session.split('.')[0]

    #Decoding the base64 format
    user_logged_in_decoded = str(base64.b64decode(user_logged_in_encoded.encode()).decode())

    #Setting the logged_in flag as false
    BASE_PATH = os.getcwd()
    db=sqlite3.connect(BASE_PATH+'/challenge1_db.db')
    cursor=db.cursor()

    cursor.execute('''update users set logged_in=? where username=?''',('False',user_logged_in_decoded))
    db.commit()
    return redirect('/challenge1/QXV0aGVudGljYXRpb25CeXBhc3M=', code=302)

####################################################################################################################################
####################################################################################################################################
################################################### RCE using SSTI in jinja2 #######################################################
####################################################################################################################################
####################################################################################################################################

@app.route('/challenge2',methods=['GET'])
def template_injection():
    if request.method=='GET':
        if request.args.get('pname'):
            return render_template_string("<font color='red'><h1>Hi "+request.args.get('pname')+", Nice to meet you!! :)</h1></font>")
        else:
            return render_template('ssti.html')

@app.route('/challenge2/submit/flag',methods=['POST'])
def submit_flag():
    user_flag = request.form['flag']
    try:
        flag_file=open("flag.txt",'r')
        flag=flag_file.readlines()
        flag=flag[0]
        flag=flag.strip('\n')
        flag_file.close()
    except:
        return "A file handling error occured!"

    print(flag)

    #Checking flag regex
    regex_check = regex.findall('CTF\{.*\}',user_flag)
    print(regex_check)
    if(len(regex_check)==0):
        return "The flag should be in CTF standard form!!"
    else:
        #Validate the flag if right or not
        if(user_flag==flag):
            return "success",200
        else:
            return "Failed",401


####################################################################################################################################
####################################################################################################################################
#######################################################  SQL INJECTION  ############################################################
####################################################################################################################################
####################################################################################################################################

@app.route('/challenge3',methods=['GET','POST'])
def sqli():
    if request.method=='GET':
        #Use port 6278 for the challenge
        return render_template('sqli.html')
    else:
        user_flag = request.form['flag']
        #Using sqlite3 to connect to DB and query the flags table
        BASE_PATH = os.getcwd()
        db=sqlite3.connect(BASE_PATH+'/challenge3_db.db')
        cursor=db.cursor()

        cursor.execute("select flag from flags where flag='"+str(user_flag)+"'")

        #fetch_one making it more challenging to extract names of all tables
        db_flag=cursor.fetchone()

        if db_flag==None:
            return render_template('sqli.html',error="Error, the flags do not match!")
        else:
            return render_template('sqli.html',flag=db_flag)

####################################################################################################################################
####################################################################################################################################
###########################################################  IDOR  #################################################################
####################################################################################################################################
####################################################################################################################################

## CTF{CRYPTOxIDOR} ##
@app.route('/challenge4',methods=['GET','POST'])
def IDOR():
    if request.method=='GET':
            return render_template('idor_login.html')

#Function to encrypt data
def sec_encrypt(plain_text):
    characters=[chr(i) for i in range(33,127)]
    character_indexes=[i for i in range(0,95)]

    character_dict=dict(zip(characters,character_indexes))
    character_dict['à']=character_dict.pop('\\') #Doing this because encrypting \ would make i \\ as python's default behaviour
    character_dict['ê']=character_dict.pop('"') #Doing this so that it doesn't break the JSON
    character_dict['¢']=character_dict.pop('/') #Doing this so that it doesn't break the URL while decrypting the user token
    character_dict['Þ']=character_dict.pop('?') #Doing this so that the data isn;t considered as a query string
    #print("\n\n",character_dict)

    #Merging all character sets to generate a strong key
    big_list=[chr(i) for i in range(48,127)]
    big_list.remove('\\')
    big_list.remove('?')
    key = ""

    while len(key)<len(plain_text):
        temp = random.choice(big_list)
        key = key+temp
        
    #print("Randomly generated key is : "+key)

    cipher_text = ""

    #encryption using random key

    for i in range(0,len(key)):
        index = (character_dict[plain_text[i]]+character_dict[key[i]]) % 94
        for temp in character_dict:
            if(character_dict[temp]==index):
                cipher_text+=temp

    #print("The Cipher text is : "+cipher_text)

    return cipher_text+'øøø'+key

def sec_decrypt(cipher_text):
    text=cipher_text.split('øøø')[0]
    key=cipher_text.split('øøø')[1]

    print("Text is: ",text)
    print("Key is: ",key)

    characters=[chr(i) for i in range(33,127)]
    character_indexes=[i for i in range(0,95)]

    character_dict=dict(zip(characters,character_indexes))
    character_dict['à']=character_dict.pop('\\') #Doing this because encrypting \ would make it \\ as python's default behaviour
    character_dict['ê']=character_dict.pop('"') #Doing this so that it doesn't break the JSON
    character_dict['¢']=character_dict.pop('/') #Doing this so that it doesn't break the URL while decrypting the user token and redirecting to the dahsboard
    character_dict['Þ']=character_dict.pop('?') #Doing this so that the data isn;t considered as a query string
    #print("\n\n",character_dict)

    #decrypting using the key we fetched from the param
    decrypted_text = ""

    for i in range(0,len(key)):
        #print(str(character_dict[text[i]])+"-"+str(character_dict[key[i]])+"% 93 is ",(character_dict[text[i]]- character_dict[key[i]])%93)
        index = (character_dict[text[i]] - character_dict[key[i]]) % 94
        for temp in character_dict:
            if(character_dict[temp]==index):
                decrypted_text+=temp
    
    print(decrypted_text)
    return decrypted_text

@app.route('/seclgn',methods=['POST'])
def idor_login():
    if request.method=='POST':

        #admin: admin@12345
        #sysadmin: sysadmin@sec
        #sysuser: sysuser@123

        #Fetching user credential data from the request
        data=request.json
        sec_uname=data['sec_uname']
        sec_pwd=data['sec_pwd']

        decrypted_uname=sec_decrypt(sec_uname)
        decrypted_pass=sec_decrypt(sec_pwd)
        
        hashed_pwd=hashlib.md5(decrypted_pass.encode()).hexdigest()

        #Using sqlite3 to connect to DB and query the users table
        BASE_PATH = os.getcwd()
        db=sqlite3.connect(BASE_PATH+'/challenge4_db.db')
        cursor=db.cursor()
        
        #Using parameterized query to prevent SQL Injection
        cursor.execute('''select * from users where username=? and password=?''',(decrypted_uname,hashed_pwd))
        record=cursor.fetchall()
        print(record)

        if len(record)>0 and record[0][0]==decrypted_uname and record[0][1]==hashed_pwd:
            login_token=sec_encrypt(decrypted_uname)+'@@@'+sec_encrypt(hashed_pwd)+'@@@'+sec_encrypt(record[0][2])
            
            #preparing the login_token response dict
            sec_login_dict={'user':sec_encrypt(decrypted_uname),'role':record[0][2],'user_token':login_token}
            return jsonify(sec_login_dict)
        else:
            return {"Error":"Invaid username or password!"}

@app.route('/secdashboard/user/<string:user_credentials>',methods=['GET'])
def secdashboard(user_credentials):
    if "@@@" not in user_credentials or "øøø" not in user_credentials:
        return render_template_string("<h1>Session Tampering Detected! This activity will be logged and monitored!</h1>")
    user_credentials=unquote(user_credentials)
    user_credentials_split=user_credentials.split("@@@")

    print("User accessed the dashboard with credentials:",user_credentials)

    decrypted_creds=[]
    for i in user_credentials_split:
        decrypted_creds.append(sec_decrypt(i))

    print("Decrypted credentials are: ",decrypted_creds)

#Using sqlite3 to connect to DB and query the users table
    BASE_PATH = os.getcwd()
    db=sqlite3.connect(BASE_PATH+'/challenge4_db.db')
    cursor=db.cursor()
        
    #Using parameterized query to prevent SQL Injection
    cursor.execute('''select * from users where username=? and password=?''',(decrypted_creds[0],decrypted_creds[1]))
    record=cursor.fetchall()
    print(record)

    if len(record)>0 and record[0][0]==decrypted_creds[0] and record[0][1]==decrypted_creds[1]:
        return render_template("idorDashboard.html",enc_user=sec_encrypt(decrypted_creds[0]),dec_user=decrypted_creds[0],Role=decrypted_creds[2])
    else:
        return render_template_string("<h1>Session Tampering Detected! This activity will be logged and monitored.</h1>")

@app.route('/user/<string:username>/ViewFiles',methods=['GET'])
def ViewFiles(username):
    username=sec_decrypt(username)
    file_list=os.listdir('challenge4/'+username)
    print(file_list)
    return render_template('Files.html',user=sec_encrypt(username),file_list=file_list)

@app.route('/user/<string:user>/preview/<string:file>',methods=['Get'])
def previewFiles(user,file):
    user=sec_decrypt(user)
    file_opened=open('challenge4/'+user+'/'+file) #Possible Path Traversal!
    file_contents=''
    
    for i in file_opened.readlines():
        file_contents+="\n"
        file_contents+=i
    
    file_opened.close()
    return render_template("file_contents.html",contents=file_contents)

@app.route('/secDashboard/getUsers',methods=['GET'])
def getUsers():
    #Using sqlite3 to connect to DB and query the flags table
        BASE_PATH = os.getcwd()
        db=sqlite3.connect(BASE_PATH+'/challenge4_db.db')
        cursor=db.cursor()

        cursor.execute("select username,role from users")

        #fetch_one making it more challenging to extract names of all tables
        record=cursor.fetchall()
        print(record)
        return jsonify(record)

####################################################################################################################
####################################################################################################################
############################################### SSRF + CSRF ########################################################
####################################################################################################################
####################################################################################################################

#Initializing Chrome Driver only for windows!
option = webdriver.ChromeOptions()
option.add_argument('headless')
driver = webdriver.Chrome(options=option)

def fetch_ss(url):
    text_source_code = re.get(url,headers={"server_sec":"pwoekf012e0-oi0-fk-913fnoiwefn-012e"}).text #Setting a custom server header so that activity can be fingerprinted
    html_file = open('source.html','w',encoding='utf-8')
    html_file.write(text_source_code)
    html_file.close()

    source_file_location=os.getcwd()+"/source.html"

    driver.get("file://"+source_file_location)
    ss_path = "static/challenge5/ss/"

    filename=random.randint(100000,9999999)
    driver.save_screenshot(ss_path+str(filename)+".png")
    print(str(filename)+" saved in destination path")
    return str(filename)+".png"

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

@app.route('/challenge5',methods=['GET','POST'])
def ssrf():
    if request.method=='GET':
        return render_template('ssrf.html',img="logo.png")
    
    elif request.method=='POST':
        input_url = request.form['url']
        print(input_url)
        if is_valid_url(input_url):
            ss_path=fetch_ss(input_url)
            return render_template('ssrf.html',img=ss_path)
        else:
            return render_template('ssrf.html',img="static/challenge5/pwn.png")

    else:
        return render_template_string("Method not Petmitted!")

@app.route('/challenge5/flag',methods=['GET'])
def flag():
    secure_server_header = request.headers.get('server_sec') #Checking for the custom server header to detect SSRF
    if secure_server_header == "pwoekf012e0-oi0-fk-913fnoiwefn-012e":
        return render_template_string("<h1>uname: admin <br> pwd: admin@wepfok1 <br> /login")
    else:
        return render_template_string("<h1><font color='red'>Trespassing detected!! This activity will be logged and monitored!</font></h1>")

@app.route('/challenge5/banned-routes',methods=['GET'])
def banned_routes():
    if request.method=='GET':
        return render_template_string("<route><br><name>/challenge5/flag</name><br><banned>True</banned><br></route>")
    else:
        return render_template_string('Method not permitted!')
if __name__=="__main__":
    app.run(debug=False,host='0.0.0.0')