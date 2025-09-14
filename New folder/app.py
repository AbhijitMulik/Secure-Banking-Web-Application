import os
import logging
import time
import random
from flask import Flask, render_template, jsonify, Response, redirect, url_for, session
from flask_socketio import SocketIO

class MalwareDetector:
    def __init__(self):
        # Malware detection configurations
        self.MALWARE_SIGNATURES = [
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        ]
        
        # Dangerous file extensions to block
        self.BLOCKED_EXTENSIONS = [
            '.exe', '.msi', '.bat', '.cmd', '.com', 
            '.scr', '.pif', '.vbs', '.js', '.jar',
            '.ps1', '.dll', '.gadget', '.hta', '.cpl'
        ]
        
        # Logging setup
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

# Flask Application Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure_malware_prevention_key'
app.config['SESSION_TYPE'] = 'filesystem'
socketio = SocketIO(app)

# Malware Detector Instance
malware_detector = MalwareDetector()

@app.route('/')
def home():
    # Reset any previous detection status
    session.pop('malware_detected', None)
    session.pop('extension_type', None)
    return render_template("simple_malware.html", show_alert=False)

@app.route('/clicked')
def clicked():
    # Generate a random dangerous extension
    random_ext = random.choice(malware_detector.BLOCKED_EXTENSIONS)
    # Store for later use
    session['extension_type'] = random_ext
    session['malware_detected'] = True
    
    # Redirect to the external site
    return redirect('/start-malware-download')

@app.route('/start-malware-download')
def start_malware_download():
    """
    Start the malware download in the background and redirect to KJSIT
    """
    # Get the selected extension (or use a default)
    file_ext = session.get('extension_type', '.exe')
    
    # Make sure extension has a dot
    if not file_ext.startswith('.'):
        file_ext = '.' + file_ext
    
    # Generate malware file name
    filename = f"malicious_file{file_ext}"
    
    # This page will redirect to KJSIT but first load the malware file in a hidden iframe
    return render_template(
        "redirect_with_malware.html", 
        malware_url=f"/download-malware{file_ext}",
        redirect_url="https://kjsit.somaiya.edu.in/en"
    )

@app.route('/download-malware<file_ext>')
def download_malware(file_ext):
    """
    Endpoint to deliver the malware file with specified extension
    """
    try:
        # Create EICAR test content - this is detected as malware by antivirus
        eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        
        # Set filename based on extension
        filename = f"malicious_file{file_ext}"
        
        # Set headers to force download
        headers = {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Length': str(len(eicar_content))
        }
        
        # Return the EICAR content as a download with the requested extension
        return Response(
            eicar_content,
            headers=headers
        )
    
    except Exception as e:
        malware_detector.logger.error(f"Download error: {e}")
        return jsonify({
            'status': 'error',
            'message': f"Error: {str(e)}"
        }), 500

@app.route('/result')
def result():
    """
    Show the result page with alert
    """
    # Get the detection status and extension from session
    detected = session.get('malware_detected', False)
    ext_type = session.get('extension_type', '.unknown')
    
    # Clear session after use
    session.pop('malware_detected', None)
    session.pop('extension_type', None)
    
    return render_template("simple_malware.html", 
                          show_alert=detected, 
                          extension_type=ext_type)

if __name__ == '__main__':
    socketio.run(app, debug=True)