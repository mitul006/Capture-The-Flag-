from flask import Flask, render_template, request, render_template_string

app = Flask(__name__)

@app.route('/',methods=['GET'])
def ftp_login():
    return render_template("FTP_login.html")

@app.route('/login',methods=['GET'])
def login():
    if request.method=='GET':
        if request.headers.get('server_sec')=='pwoekf012e0-oi0-fk-913fnoiwefn-012e':
            if (request.args.get('uname')=="admin") and (request.args.get('pwd')=="admin@wepfok1"):
                return render_template_string("<h1><font color='green'>CTF{RequestForgeryExpert}</font></h1>")
            else:
                return render_template_string("<h1><font color='red'>Naah mate, try again!</font></h1>")
        else:
            return render_template_string("<h1><font color='red'>Tresspassing detected!! This activity will be logged and monitored!!")
    else:
        render_template_string('<h1>Method not Permitted!</h1>')

if __name__=="__main__":
    app.run(debug=False,port=2112)