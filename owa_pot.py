import os
import base64
import struct
import logging
import binascii
from functools import wraps
from flask import (
  Flask, redirect, render_template, request,
  send_from_directory, Response, make_response
)
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Configure logging
log_file = os.getenv("LOG_FILE", "honeypot.log")
logger = logging.getLogger("honeypot")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(log_file)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter(
  "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
fh.setFormatter(formatter)
logger.addHandler(fh)


def create_app(test_config=None):
  app = Flask(__name__, instance_relative_config=True)

  # Load configuration from environment variables
  app.config.from_mapping(
    SECRET_KEY=os.getenv("SECRET_KEY", None),
  )

  # Ensure the instance folder exists
  try:
    os.makedirs(app.instance_path)
  except OSError:
    pass

  # --- Error Handlers ---
  @app.errorhandler(404)
  def page_not_found(e):
    return render_template("404.html"), 404

  @app.errorhandler(403)
  def page_no_access(e):
    return render_template("403.html"), 403

  @app.errorhandler(401)
  def page_auth_required(e):
    return render_template("401.html"), 401

  app.register_error_handler(404, page_not_found)
  app.register_error_handler(403, page_no_access)
  app.register_error_handler(401, page_auth_required)

  # --- Authentication Functions ---
  def check_auth(username, password):
    # Log basic authentication attempts (always fail)
    logger.info(
      f"{request.base_url} | Basic Auth Attempt: {username}:{password} | "
      f"IP: {request.remote_addr} | UA: {request.headers.get('User-Agent')}"
    )
    return False  # Always fail authentication to simulate honeypot

  def authenticate():
    """
    Returns a 401 response with both Basic and NTLM authentication
    challenges.
    """
    resp = Response(
      "Could not verify your access level for that URL.\n"
      "You have to login with proper credentials", 401
    )
    # Include both challenges in the response headers
    resp.headers.add("WWW-Authenticate", 'Basic realm="' + os.getenv("BASIC_REALM_NAME", "Login Required") + '"')
    resp.headers.add("WWW-Authenticate", "NTLM")
    return resp

  def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
      # Check for NTLM authentication (Flask's request.authorization only parses Basic)
      auth_header = request.headers.get("Authorization", "")
      if auth_header.startswith("NTLM"):
        # I guess need to do check for necessary bytes
        try:
          # Decode NTLM response
          ntlm_data = base64.b64decode(auth_header.split(' ')[1])

          # Unpack the response header. The format "12xhhihhihhihhi" skips the first 12 bytes
          # and then reads several short and integer values.
          lmlen, lmmax, lmoff, ntlen, ntmax, ntoff, domlen, dommax, domoff, userlen, usermax, useroff = struct.unpack(
            "12xhhihhihhihhi", ntlm_data[:44]
          )

          # Extract and convert the LM and NT hashes.
          lmhash = binascii.b2a_hex(ntlm_data[lmoff:lmoff + lmlen]).decode('ascii')
          nthash = binascii.b2a_hex(ntlm_data[ntoff:ntoff + ntlen]).decode('ascii')

          # Extract and decode the domain and username. Remove null bytes.
          domain = ntlm_data[domoff:domoff + domlen].replace(b"\x00", b"").decode('utf-8', errors='ignore')
          user = ntlm_data[useroff:useroff + userlen].replace(b"\x00", b"").decode('utf-8', errors='ignore')

          # Determine the type based on the NT hash length.
          if ntlen == 24:
            # NetNTLMv1
            ntlm_str = "NetNTLMv1:" + user + "::" + domain + ":" + lmhash + ":" + nthash
          else:
            # NetNTLMv2
            ntlm_str = "NetNTLMv2:" + user + "::" + domain + ":" + nthash[:32] + ":" + nthash[32:]
        except:
          # Decode NTLM failed
          ntlm_str = "ERROR DECODING TOKEN"

        logger.info(
          f"{request.base_url} | NTLM Auth Attempt: {auth_header} | NTLM Decoded: {ntlm_str} | "
          f"IP: {request.remote_addr} | UA: {request.headers.get('User-Agent')}"
        )
        return authenticate()
      # Then check for Basic authentication
      auth = request.authorization
      if not auth or not check_auth(auth.username, auth.password):
        return authenticate()
      return f(*args, **kwargs)
    return decorated

  # --- Decorators for Response Headers ---
  def add_response_headers(headers=None):
    """Decorator that adds the given headers to the response."""
    if headers is None:
      headers = {}
    def decorator(f):
      @wraps(f)
      def decorated_function(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        for header, value in headers.items():
          resp.headers[header] = value
        return resp
      return decorated_function
    return decorator

  def changeheader(f):
    return add_response_headers({
      # server header set in gunicorn.conf.py
      # "Server": "Microsoft-IIS/10.0",
      "X-Powered-By": "ASP.NET"
    })(f)

  # --- Routes ---
  @app.route('/Abs/')
  @app.route('/aspnet_client/')
  @app.route('/Autodiscover/')
  @app.route('/AutoUpdate/')
  @app.route('/CertEnroll/')
  @app.route('/CertSrv/')
  @app.route('/Conf/')
  @app.route('/DeviceUpdateFiles_Ext/')
  @app.route('/DeviceUpdateFiles_Int/')
  @app.route('/ecp/')
  @app.route('/Etc/')
  @app.route('/EWS/')
  @app.route('/Exchweb/')
  @app.route('/GroupExpansion/')
  @app.route('/Microsoft-Server-ActiveSync/')
  @app.route('/OAB/')
  @app.route('/ocsp/')
  @app.route('/PhoneConferencing/')
  @app.route('/PowerShell/')
  @app.route('/Public/')
  @app.route('/RequestHandler/')
  @app.route('/RequestHandlerExt/')
  @app.route('/Rgs/')
  @app.route('/Rpc/')
  @app.route('/rpc/')
  @app.route('/RpcWithCert/')
  @app.route('/UnifiedMessaging/')
  @changeheader
  @requires_auth
  def stub_redirect():
    return redirect('/')

  @app.route('/owa/auth/15.1.2507/themes/resources/segoeui-regular.ttf', methods=['GET'])
  @changeheader
  def font_segoeui_regular_ttf():
    return send_from_directory(app.static_folder, path='segoeui-regular.ttf', conditional=True)

  @app.route('/owa/auth/15.1.2507/themes/resources/segoeui-semilight.ttf', methods=['GET'])
  @changeheader
  def font_segoeui_semilight_ttf():
    return send_from_directory(app.static_folder, path='segoeui-semilight.ttf', conditional=True)

  @app.route('/owa/auth/15.1.2507/themes/resources/favicon.ico', methods=['GET'])
  @changeheader
  def favicon_ico():
    return send_from_directory(app.static_folder, path='favicon.ico', conditional=True)

  @app.route('/owa/auth.owa', methods=['GET', 'POST'])
  @changeheader
  def auth():
    ua = request.headers.get("User-Agent")
    ip = request.remote_addr
    if request.method == "GET":
      return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=3&url=', 302)
    else:
      # Read credentials from form data (if present)
      username = request.form.get("username", "")
      password = request.form.get("password", "")
      passwordText = request.form.get("passwordText", "")
      logger.info(
        f"{request.base_url} | Form Auth Attempt: {username}:{password} | "
        f"Extra: {passwordText} | IP: {ip} | UA: {ua}"
      )
      return redirect('/owa/auth/logon.aspx?replaceCurrent=1&reason=2&url=', 302)

  @app.route('/owa/auth/logon.aspx', methods=['GET'])
  @changeheader
  def owa():
    return render_template("outlook_web.html")

  @app.route('/')
  @app.route('/exchange/')
  @app.route('/webmail/')
  @app.route('/exchange')
  @app.route('/webmail')
  @changeheader
  def index():
    return redirect('/owa/auth/logon.aspx?replaceCurrent=1&url=', 302)

  return app

# Expose the application instance for Gunicorn
app = create_app()

if __name__ == '__main__':
  host = os.getenv("HOST", "0.0.0.0")
  port = int(os.getenv("PORT", 1337))
  debug = os.getenv("DEBUG", "False").lower() in ["true", "1", "yes"]
  app.run(debug=debug, port=port, host=host)
