from flask import Flask, render_template, redirect, request, make_response, session, url_for, escape, flash, abort
from wtforms import SubmitField, PasswordField, StringField
from wtforms.validators import DataRequired, email, Length
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import namedtuple
from flask_mail import Mail, Message
import warnings, smtplib, threading, os, time, random, string, datetime

non_real_useragents = ['facebookexternalhit', 'Facebot', 'googlebot', 'adsbot', 'bingbot', 'Slurp']
warnings.filterwarnings('ignore')
main_urls = ('index', 'login', 'signup')
dashboard_urls = ('dashboardindex', 'dashboard')
user_info = namedtuple('user_info', ['username', 'email', 'password', 'phone_number'])
new_user_info = namedtuple('new_user_info',
						   ['usersname', 'email', 'password', 'phone_number', 'link', 'session_time'])
shorted_url_info = namedtuple('shorted_url_info', ['encrypted_url', 'real_url', 'visitors_number'])
users_table = {}
new_users = {}
shorted_urls = {}
emails_address = []
active_links = []
settings = {'users_table': os.path.join(os.path.dirname(__file__), 'templates/database/users_table.bin'),
			'new_users': os.path.join(os.path.dirname(__file__), 'templates/database/new_users.bin'),
			'dashboard': os.path.join(os.path.dirname(__file__), 'templates/dashboard'),
			'shorted_urls': os.path.join(os.path.dirname(__file__), 'templates/database/shorted_urls.bin')}
database_user_tables_fetched = database_new_users_fetched = database_shorted_url_fetched = database_fetched = False
script_domain_name = ''
app = Flask(__name__)


class Security:
	def encryption(self, data, key=10, passphrase_len=3):
		data = str(data)
		encrypted_data = ''
		main_string = ''
		for i in range(1, len(data) + 1):
			char = ord(data[i - 1])
			pr = string.printable.translate(string.printable.maketrans({'$': '', '\\': '', '\'': '', '"': '', '|': ''}))
			passphrase = [random.choice(list(pr)) for x in range(passphrase_len)]
			passphrase[int(passphrase_len / 2)] = '$'
			passphrase = ''.join(passphrase)
			char = char + i * key
			main_string += chr(int(char))
			encrypted_data += passphrase.replace('$', chr(int(char)))
		encrypted_data += ' /[k=%%%s%%p=%%%s%%]/' % (key, passphrase_len)
		return encrypted_data.encode('utf-8')

	def decryption(self, data):
		args = data.split('%]/')
		args = args[len(args) - 2].split(' /[')
		data = str(args[0])
		args = args[len(args) - 1]
		key, chunck_size = int(args.split('%')[1]), int(args.split('%')[len(args.split('%')) - 1])
		end_index, start_index, decrypted_data, main_string = chunck_size, 0, '', ''
		for i in range(1, int(len(data) / chunck_size) + 1):
			char = data[start_index: end_index]
			char = char[int(len(char) / 2)]
			main_string += char
			start_index, end_index = end_index, end_index + chunck_size
		for i in range(1, len(main_string) + 1):
			decrypted_data += chr(ord(main_string[i - 1]) - i * key)
		return decrypted_data

	def vertification_code(self):
		return ''.join([random.choice(string.ascii_letters + string.digits) for i in range(9)])

	class send_email_with_nonuni(threading.Thread):
		def startx(self, username, password, Name, _from, _to, message, smtp, port):
			self.username, self.password, self._from, self._to, self.message, self.smtp, self.port, self.Name = username, password, _from, _to, message, smtp, port, Name
			self.start()

		def run(self):
			try:
				server = smtplib.SMTP_SSL(self.smtp, self.port)
				server.ehlo()
				server.login(self.username, self.password)
				msg = MIMEMultipart('text')
				msg['Subject'] = 'activation shorten url'
				from_email = str(Security().encryption(self._from))
				from_email = '%s <%s@dwcl.%s>' % (
					self.Name, ''.join([x for x in from_email.split(' /[')[0].replace(r'x', '').translate(
						from_email.maketrans({'"': '', "'": '', '\\': ''})) if
										x in string.ascii_letters + string.digits])[:random.randint(3, 10)],
					'digiworldcom.com')
				msg['From'] = from_email
				msg['To'] = self._to
				bypass_spam = str(Security().encryption(''.join(
					[random.choice(list(string.ascii_letters + string.digits)) for x in
					 range(random.choice(list(range(7, 15))))]))).replace('\n', '') + '\r\n'
				bypass_spam = bypass_spam.strip().replace('b', '').translate(
					bypass_spam.maketrans({'"': '', "'": '', '\\': '/'})).split(' ')[0].replace('x', '')
				bypass_spam = 'http://' + ''.join([x for x in bypass_spam if x not in string.punctuation]) + '.com'
				html = MIMEText(self.message, 'html')
				msg.attach(html)
				msg = bypass_spam + '\n' + msg.as_string()
				server.sendmail('', self._to, self.message)
				server.quit()
			except Exception as e:
				print(e)
				print('Message Has Not Send Check The Logs')

	def check_cookies(self, cookie_name, cookie_value):
		if cookie_name in request.cookies.keys():
			cookie_data = Security().decryption(request.cookies[cookie_name]).split('%')
			if float(cookie_data[1]) > time.time() and cookie_data[0] == cookie_value:
				return True
			return False
		else:
			return False

	def set_cookie(self, response_path, cookie_name, cookie_value, path, encryption_key=10,
				   expiration_time: 'time in seconds' = 3600):
		resp = make_response(redirect(response_path))
		cookie_value = self.encryption(cookie_value + '%' + str(time.time() + expiration_time), encryption_key)
		resp.set_cookie(cookie_name, cookie_value, path=path)
		return resp

	def get_external_ip(self):
		return str(request.remote_addr)


class database:
	def add_new_visitor(self, encrypted_url):
		shorted_urls_file = open(settings['shorted_urls'], 'r+')
		urls = shorted_urls_file.readlines()
		shorted_urls_file.seek(0)
		for url in urls:
			url = Security().decryption(eval(url).decode()).split('-:-')
			if encrypted_url == url[0]:
				shorted_urls_file.write(str(
					Security().encryption('%s-:-%s-:-%s' % (url[0], url[1], int(url[2]) + 1),
										  random.randint(7, 20))) + '\n')
				shorted_urls[url[0]] = shorted_url_info(url[0], url[1], int(url[2]) + 1)
			else:
				shorted_urls_file.write(str(
					Security().encryption('%s-:-%s-:-%s' % (url[0], url[1], url[2]),
										  random.randint(7, 20))) + '\n')
		shorted_urls_file.truncate()
		shorted_urls_file.close()

	def Add_New_User(self, username, password, email_address, phone):
		file = open(settings['new_users'], 'a+')
		link = ''.join(
			[random.choice(string.ascii_letters + string.digits) for x in
			 range(random.choice(list(range(9, 100))))])
		file.write(str(
			Security().encryption(
				':'.join([username, password, email_address, phone, str(time.time() + 3600), link]),
				12)) + '\n')
		file.close()
		return link

	class Create_user(threading.Thread):
		def startx(self, username, password, email_address, phone_number):
			self.username = username
			self.password = password
			self.email_address = email_address
			self.phone_number = phone_number
			self.start()

		def run(self):
			global active_links, new_users
			active_links, new_users = [], {}
			users_table_file = open(settings['users_table'], 'a+')
			users_table_file.write(str(Security().encryption(
				':'.join([self.username, self.password, self.email_address, self.phone_number]))) + '\n')
			users_table_file.flush()
			users_table_file.close()
			new_users_table_file = open(settings['new_users'], 'r+')
			new_users_data = new_users_table_file.readlines()
			new_users_table_file.seek(0)
			for user in new_users_data:
				Args = Security().decryption(eval(user).decode('utf-8')).split(':')
				username = Args[0]
				password = Args[1]
				email_address = Args[2]
				phone = Args[3]
				session_time = Args[len(Args) - 2]
				link = Args[len(Args) - 1]
				if username != self.username:
					active_links += [link]
					new_users_table_file.write(user)
					new_users[username] = new_user_info(username, email_address, password, phone, link,
														session_time)
					if email_address not in emails_address:
						emails_address.append(email_address)
			new_users_table_file.truncate()
			new_users_table_file.close()

	class file_watcher(threading.Thread):
		def run(self):
			self.user_tables().daemon = True
			self.new_users().daemon = True
			self.shorted_urls().daemon = True
			self.user_tables().start()
			self.shorted_urls().start()
			self.new_users().start()

		class user_tables(threading.Thread):
			last_modification_time = ''

			def run(self):
				global database_user_tables_fetched
				while True:
					if os.path.exists(settings['users_table']):
						if os.path.getmtime(
								settings[
									'users_table']) != self.last_modification_time:
							self.last_modification_time = os.path.getmtime(settings['new_users'])
							users = open(settings['users_table'], 'r+')
							for i in users.readlines():
								user_data = Security().decryption(eval(i).decode()).split(':')
								email_address = user_data[2]
								username = user_data[0]
								password = user_data[1]
								phone_number = user_data[3]
								info = user_info(username=username, email=email_address, password=password,
												 phone_number=phone_number)
								if email_address not in emails_address:
									emails_address.append(email_address)
								if username.lower() not in users_table.keys():
									users_table[username] = info
								elif username.lower() in users_table.keys() and (
										users_table[username][1] != email_address or users_table[username][
									2] != password):
									users_table[username] = info
							self.last_modification_time = os.path.getmtime(settings['users_table'])
							database_user_tables_fetched = True
							users.close()

		class new_users(threading.Thread):
			last_modification_time = ''

			def run(self):
				global database_new_users_fetched
				if os.path.exists(settings['new_users']):
					while True:
						if os.path.getmtime(settings['new_users']) != self.last_modification_time:
							new_users_file = open(settings['new_users'], 'r+')
							data = new_users_file.readlines()
							new_users_file.seek(0)
							for i in data:
								Args = Security().decryption(eval(i).decode()).split(':')
								username = Args[0]
								password = Args[1]
								email_address = Args[2]
								phone = Args[3]
								session_time = Args[len(Args) - 2]
								link = Args[len(Args) - 1]
								global active_links
								if time.time() < float(session_time):
									active_links += [link]
									new_users_file.write(i)
									new_users[username] = new_user_info(username, email_address, password, phone,
																		link,
																		session_time)
									if email_address not in emails_address:
										emails_address.append(email_address)
								else:
									del active_links[active_links.index(link)]
									del new_users[username]
							new_users_file.truncate()
							new_users_file.close()
							self.last_modification_time = os.path.getmtime(settings['users_table'])
							database_new_users_fetched = True

		class shorted_urls(threading.Thread):
			last_modification_time = ''

			def run(self):
				global database_shorted_url_fetched
				if os.path.exists(settings['shorted_urls']):
					while True:
						if os.path.getmtime(settings['shorted_urls']) != self.last_modification_time:
							shorted_url_file = open(settings['shorted_urls'], 'r+')
							data = shorted_url_file.readlines()
							for i in data:
								Args = Security().decryption(eval(i).decode()).split('-:-')
								encrypted_url, real_url, visitors = Args[0], Args[1], Args[2]
								shorted_urls[encrypted_url] = shorted_url_info(encrypted_url=encrypted_url,
																			   real_url=real_url,
																			   visitors_number=visitors)
							self.last_modification_time = os.path.getmtime(settings['shorted_urls'])
							database_shorted_url_fetched = True

	class database_fetched(threading.Thread):
		def run(self):
			global database_fetched
			while True:
				if database_shorted_url_fetched and database_user_tables_fetched and database_new_users_fetched:
					database_fetched = True
					break

	class delete_new_user(threading.Thread):
		def startx(self, username):
			self.username = username
			self.start()

		def run(self):
			new_users_file = open(settings['new_users'], 'r+')
			data = new_users_file.readlines()
			new_users_file.seek(0)
			for i in data:
				Args = Security().decryption(eval(i).decode()).split(':')
				username = Args[0]
				if username != self.username:
					new_users_file.write(i)
				else:
					del new_users[username]
			new_users_file.truncate()
			new_users_file.close()


class website_forms:
	class shorten_form(FlaskForm):
		url = StringField('url', validators=[DataRequired()])
		shorten = SubmitField('Short Link')

	class Login_Form(FlaskForm):
		username = StringField('username', validators=[DataRequired()])
		password = PasswordField('password', validators=[DataRequired()])
		login = SubmitField('Login')

	class Signup_Form(FlaskForm):
		username = StringField('username', validators=[DataRequired()])
		password = PasswordField('password', validators=[DataRequired(), Length(min=7, max=64)])
		confirm_password = PasswordField('confirm_password', validators=[DataRequired()Length(min=7, max=64)])
		email_address = StringField('email address', validators=[DataRequired(), email()])
		phone = StringField('phone number')
		signup = SubmitField('Sign Up')


mail_settings = {
	"MAIL_SERVER": 'Your SMTP SERVER',
	"MAIL_PORT": 465,
	"MAIL_USE_TLS": False,
	"MAIL_USE_SSL": True,
	"MAIL_USERNAME": 'SMTP USERNAME',
	"MAIL_PASSWORD": 'SMTP PASSWORD'
}
app.config.update(mail_settings)
mail = Mail(app)
app.secret_key = Security().encryption('ABDOANDTPCT', 12)


def main_script_url():
	global script_domain_name
	script_domain_name = 'http://' + request.host


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
def index():
	main_script_url()
	form = website_forms().shorten_form()
	if str(request.method).lower() == 'post':
		if form.validate_on_submit():
			url = form.url.data
			encrypted_url = Security().encryption(url, random.randint(1, 20))
			while encrypted_url in shorted_urls and len(encrypted_url) > 0:
				encrypted_url = Security().encryption(url, random.randint(1, 20))
			encrypted_url = str(encrypted_url).translate(str.maketrans(
				dict(zip(list(string.punctuation), [' ' for x in range(len(string.punctuation))])))).replace(' ', '')

			def random_chunk(start, end):
				chunk_size = random.randint(start, end)
				chunks = [encrypted_url[x:x + chunk_size] for x in range(0, len(encrypted_url), chunk_size)]
				random_chunk = chunks[random.randint(0, len(chunks) - 1)]
				return random_chunk

			parsed_url = random_chunk(random.randint(0, 10), random.randint(15, 60))
			while parsed_url in shorted_urls:
				parsed_url = random_chunk(random.randint(0, 10), random.randint(15, 60))
			parsed_url = script_domain_name + '/link/%s' % (parsed_url)
			shorted_urls_file = open(settings['shorted_urls'], 'a+')
			shorted_urls_file.write(str(
				Security().encryption('%s-:-%s-:-%s' % (parsed_url, url, 0),
									  random.randint(7, 20))) + '\n')
			shorted_urls[parsed_url] = shorted_url_info(parsed_url, url, 0)
			shorted_urls_file.close()
			database().file_watcher().shorted_urls().start()
			return render_template('index.html', form=form, valid_url=parsed_url)

	return render_template('index.html', form=form, valid_url=None)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def Url_Catcher(path):
	main_script_url()
	path = path.split('.')[0]
	if path.lower() in main_urls:
		return redirect('/%s' % path)
	elif path.replace('/', '') in dashboard_urls:
		if Security().check_cookies('logged', Security().get_external_ip()):
			return redirect('/%s' % path.strip('/'))
		else:
			return redirect(url_for('login'))
	else:
		title = 'Error - You are lost'
		return render_template('404.html', title=title)


@app.errorhandler(500)
def internal_server_error(e):
	return render_template('404.html'), 500


@app.route('/login', methods=['GET', 'POST'], strict_slashes=False)
def login():
	main_script_url()
	form = website_forms().Login_Form()
	error = None
	title = 'Login Page'
	if Security().check_cookies('logged', Security().get_external_ip()):
		return 'hello sir'
	else:
		if form.validate_on_submit():
			if str(request.method).lower() == 'post':
				if form.username.data.lower() in users_table.keys():
					if form.password.data == users_table[form.username.data.lower()][2]:
						resp = make_response(redirect(url_for('login')))
						cookie = Security().get_external_ip() + "%" + str(time.time() + 3600)
						resp.set_cookie('logged', Security().encryption(cookie, 8), path=settings['dashboard'])
						resp.set_cookie('logged', Security().encryption(cookie, 8), path=url_for('login'))
						return resp
					else:
						error = 'Invalid Username Or Password'
				else:
					error = 'Invalid Username Or Password'

	return render_template('login.html', form=form, title=title, error=error)


@app.errorhandler(404)
def page_not_found(e):
	title = 'Error - You are lost'
	main_script_url()
	return render_template('404.html', title=title), 404


@app.route('/link/<path:path>')
def redirector(path):
	main_script_url()
	path = script_domain_name + '/link/%s' % path
	if path in shorted_urls.keys():
		if any([x for x in non_real_useragents if x in str(request.user_agent).lower()]):
			return ''
		else:
			database().add_new_visitor(path)
			return redirect(shorted_urls[path][1])
	else:
		print(path, shorted_urls)
		abort(404)


@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
	sign_up_form = website_forms().Signup_Form()
	error = None
	main_script_url()
	if sign_up_form.validate_on_submit():
		if str(request.method).lower() == 'post':
			username = sign_up_form.username.data
			password = sign_up_form.password.data
			confirm_password = sign_up_form.confirm_password.data
			email_address = sign_up_form.email_address.data
			phone = sign_up_form.phone.data if sign_up_form.phone.data.__len__() > 0 else ''
			if password == confirm_password and username not in users_table.keys() and username not in new_users.keys() and email_address not in emails_address:
				link = str(script_domain_name) + '/reg/' + database().Add_New_User(username, password,
																				   email_address, phone)
				message = """
				<html><head></head><body><table style="background:#2a3644;padding:40px 0 20px 0" cellspacing="0" cellpadding="0" border="0" align="center" width="800">
          <tbody><tr>
            <td>
              <table style="margin:0 auto" cellspacing="0" cellpadding="0" border="0" bgcolor="#FFF" align="center" width="480">
                <tbody><tr>
                  <td style="padding:40px 0px 0px 0px" valign="top">
                    <table cellspacing="0" cellpadding="0" border="0" align="center">
                      <tbody><tr>
                        <td class="m_-3763620718889647047td-pad10-wide" style="padding:0px 20px 0px 20px;font-weight:400;font-size:13px;letter-spacing:0.025em;line-height:26px;color:#000;font-family:'Poppins',sans-serif;background:white" align="center">
                            <span style="font-weight:300;font-size:24px;letter-spacing:0.025em;line-height:23px;color:#8fbe00;font-family:'Poppins',sans-serif">
  Confirm Your TPCT-Url Account<br>
</span>
  <p>Thanks for creating a TPCT-Url account. We are happy you found us. To confirm your account, please click the button below.</p>
  <table class="m_-3763620718889647047table-button180" style="margin:0;border-radius:3px" cellspacing="0" cellpadding="0" border="0" bgcolor="#8FBE00" align="center" width="220" height="45">
  <tbody><tr>
    <td style="padding:5px 5px" align="center" valign="middle">
              <a style="font-weight:500;font-size:17px;letter-spacing:0.025em;line-height:26px;color:#fff;font-family:'Poppins',sans-serif;text-decoration:none" target="_blank" href="%s">
              Confirm Account
      </a>
    </td>
  </tr>
</tbody></table>
                        <p>Thank you for choosing TPCT-Url! We hope that you enjoy our rock solid services.</p>
                        <p>This url is valid for only one hour.</p></td>
                      </tr>
                    </tbody></table>
                  </td>
                </tr>
              </tbody></table>
            </td>
          </tr>
        </tbody></table>
</body></html>""" % link
				message = Message('Activation Url', recipients=[email_address], html=message,
								  sender=mail_settings['MAIL_USERNAME'])
				mail.send(message)
				database().file_watcher().new_users().start()
				return redirect(url_for('login'))
			else:
				error = 'Something went wrong please try again'
	return render_template('signup.html', form=sign_up_form, title='Sign-up', error=error)


@app.route('/reg/<reg_url>', methods=['GET'])
def reg(reg_url):
	if reg_url in active_links:
		for i in new_users.keys():
			if new_users[i][4] == reg_url:
				database().Create_user().startx(new_users[i][0], new_users[i][2], new_users[i][1], new_users[i][3])
				database().file_watcher().user_tables().start()
				database().delete_new_user().startx(new_users[i][0])
		return redirect(url_for('login'))
	abort(404)


@app.route('/dashboard')
@app.route('/dashboard/index')
def dashboard_index():
	if Security().check_cookies('logged', Security().get_external_ip()):
		return 'hello sir'
	else:
		return redirect(url_for('login'))
	pass


if __name__ == '__main__':
	database().file_watcher().daemon = True
	database().file_watcher().start()
	database().database_fetched().start()
	while not database_fetched:
		pass
	app.run('0.0.0.0', 80, debug=False)
	while True:
		if not database().file_watcher().isAlive():
			os._exit(1)
			break
