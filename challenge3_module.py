from flask import Flask, render_template, request, redirect, make_response, jsonify, render_template_string
import sqlite3
import os

app = Flask(__name__)

#REST API 
@app.route('/',methods=['GET','POST'])
def submit_flag():
    if request.method=='GET':
        return render_template('submit_challenge3.html')
    else:
        user_flag=request.form['flag']
        user_isAdmin=request.form['isAdmin']

        #Using sqlite3 to connect to DB and query the flags table
        BASE_PATH = os.getcwd()
        db=sqlite3.connect(BASE_PATH+'/challenge3_final.db')
        cursor=db.cursor()

        #Selecting the true flag from the table
        cursor.execute('select flag from flags where isAdmin="Yes"')
        db_flag=cursor.fetchone()
        db_flag=db_flag[0] #Just fetching the value out of the set
        
        #Explicitly making the isAdmin column injectable
        ##### BAD CODING PRACTICE #####
        cursor.execute('select isAdmin from flags where isAdmin="'+user_isAdmin+'"')
        db_isAdmin=cursor.fetchall()
        print(db_isAdmin)

        if db_isAdmin!=None and (db_isAdmin[0][0]=='Yes' or db_isAdmin[0]=='Yes') and user_flag==db_flag:
            return render_template('submit_challenge3.html',success="Congratulations!! You are an SQLI expert",flag=db_flag,isAdmin_bool=db_isAdmin)
        elif user_flag!=db_flag:
            return render_template('submit_challenge3.html',flag_error="HAHAHAAH wrong flag bro! You thought it'd be that easy?",isAdmin_bool=db_isAdmin)
        else:
            return render_template('submit_challenge3.html',error="There is an error that the server cannot comprehend! Bro are you a wizard?",isAdmin_bool=db_isAdmin)

if __name__=="__main__":
    app.run(debug=False,port=6278)