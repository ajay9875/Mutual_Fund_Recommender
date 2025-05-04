from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.contrib import messages
from Myapp.models import Contact
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from .models import ProfilePic
import os
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from django.core.files.storage import default_storage
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import os
from django.conf import settings
from django.utils.timezone import now
from django.utils import timezone
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings

import random

#import yfinance as yf
#import numpy as np
#from sklearn.metrics.pairwise import cosine_similarity
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseServerError
from django.shortcuts import render

def my_view(request):
    try:
        # Some code that might raise an exception
        raise ValueError("Something went wrong!")
    except ValueError:
        # Trigger a custom 500 error page
        return HttpResponseServerError(render(request, "404.html"))

'''
def get_real_time_data(ticker):
    """Fetch real-time data (Closing prices) from Yahoo Finance."""
    try:
        fund = yf.Ticker(ticker)
        historical_data = fund.history(period="5y")  # Fetch 5 years of data
        if historical_data.empty:
            return None
        return historical_data['Close']  # You can extend this to use other metrics like volume, etc.
    except Exception as e:
        print(f"Error fetching data for {ticker}: {e}")
        return None

def content_based_recommendation(company_type, risk_level, top_n=5):
    """Recommend funds based on company type and risk level using Yahoo Finance data."""
    # Define fund tickers for different types
    fund_tickers = {
        'equity': 'VFINX',  # Example: Vanguard 500 Index Fund
        'debt': 'BND',  # Example: Vanguard Total Bond Market ETF
        'international': 'VTIAX',  # Example: Vanguard Total International Stock Index Fund
    }

    # Use the ticker corresponding to the selected company type
    ticker = fund_tickers.get(company_type, 'VFINX')

    # Fetch real-time data using the ticker
    real_time_data = get_real_time_data(ticker)
    if real_time_data is None:
        return ['No data available for this fund type.']

    # Calculate average return rate (percentage change)
    avg_return = real_time_data.pct_change().mean() * 100  # Calculate average return rate

    # Prepare a list of recommended funds (using mock data here)
    fund_data = [(ticker, company_type, risk_level, avg_return)]  # Example: [("VFINX", "equity", "low", avg_return)]

    # Generate a feature matrix based on the company type, risk, and average return rate
    feature_matrix = np.array([[f[1] == company_type, f[2] == risk_level, f[3]] for f in fund_data])

    # Ensure feature_matrix is 2D
    if feature_matrix.ndim == 1:
        feature_matrix = feature_matrix.reshape(-1, 1)

    # Calculate cosine similarity based on the features
    similarities = cosine_similarity(feature_matrix)

    # Get similarity scores for the first fund in the list
    scores = list(enumerate(similarities[0]))  # Use fund at index 0 as a reference
    scores = sorted(scores, key=lambda x: x[1], reverse=True)[1:top_n+1]  # Sort based on similarity scores

    # Return the recommended funds based on similarity scores
    recommended_funds = [fund_data[i[0]] for i in scores]
    return recommended_funds
'''
'''
def classify_risk(avg_return):
    """Classify mutual funds into risk categories based on return rate."""
    if avg_return >= 12:  
        return "High Risk"
    elif 6 <= avg_return < 12:  
        return "Moderate Risk"
    else:  
        return "Low Risk"

def get_real_time_fund_data(fund_ticker):
    """Fetch mutual fund details dynamically from Yahoo Finance."""
    try:
        fund = Ticker(fund_ticker)

        # Get basic fund details
        summary = fund.summary_detail.get(fund_ticker, {})
        quote_info = fund.quote_type.get(fund_ticker, {})

        # Get 5-year historical prices
        history = fund.history(period="5y")
        if history.empty:
            return None

        # Calculate return rate (avg annualized return)
        avg_return = history['close'].pct_change().mean() * 100

        # Classify risk level dynamically
        risk_level = classify_risk(avg_return)

        # Prepare response data
        fund_details = {
            "Name": quote_info.get('longName', 'N/A'),
            "Fund Type": quote_info.get('quoteType', 'N/A'),
            "Risk Level": risk_level,
            "Expense Ratio": summary.get('expenseRatio', 'N/A'),
            "1-Year Return": summary.get('trailingAnnualDividendYield', 'N/A'),
            "5-Year Average Return": round(avg_return, 2),
            "Fund Ticker": fund_ticker,
        }

        return fund_details

    except Exception as e:
        print(f"Error fetching fund data: {e}")
        return None

def fund_search(request):
    """Django view to search for mutual funds in real-time."""
    fund_data = None

    if request.method == "POST":
        fund_ticker = request.POST.get("fund_ticker")
        
        if fund_ticker:
            fund_data = get_real_time_fund_data(fund_ticker)

    return render(request, "fund_search.html", {"fund_data": fund_data})
'''
def default(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('landing_page')
    
# Landing / Home page rendering for not logged in user(Redirect to dashboard if logged in user found)
def landing_page(request):
    return render(request,'Default.html')

@never_cache
def userdashboard(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('landing_page')

    if 'session_expiry' not in request.session:
        request.session['session_expiry'] = request.session.get_expiry_date().timestamp()

    expiry_time = request.session['session_expiry']
    current_time = datetime.now().timestamp()
    remaining_time = max(0, int(expiry_time - current_time))

    full_name = request.session.get('full_name', '').upper().strip()
    username = request.session.get('username', '')
    # Check if the user has a ProfilePic object and fetch the filename
    
    try:
        profilepic = ProfilePic.objects.get(username=request.user).filename.url
    except ProfilePic.DoesNotExist:
        profilepic = None  # No profile picture found

    if not full_name:
            full_name = username

    recommended_funds = request.session.get('recommended_funds', [])

    context = {
        "remaining_time": remaining_time,
        "full_name": full_name,
        "profilepic": profilepic,  # Pass profile picture URL
        "recommended_funds": recommended_funds,
        "MEDIA_URL": settings.MEDIA_URL,  # Pass MEDIA_URL explicitly
    }
    print(f'Profile picture: {profilepic}')
    return render(request, 'Index.html', context)

# Handle login request by user
def loginUser(request):
    if request.user.is_authenticated:
        return redirect("dashboard")  # Prevent logged-in users from seeing login page
    
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            
            # Store user details in session
            request.session['username'] = user.username  # Store username
            #request.session['profilepic'] = user.profile_picture  # Store username
            request.session['full_name'] = f"{user.first_name} {user.last_name}"  # Store full name
            messages.success(request, "You have successfully logged in!")
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid Credentials! Please try again.")
            return redirect('login')
        
    context = {
        'title': 'User Login',
        'header': 'Login Now'
    }
    return render(request, 'Login.html', context)

# Handle logout request by user
@never_cache
@login_required
def logoutUser(request):
    logout(request)
    messages.success(request, "You have successfully logged out!")
    return redirect('login')

#---- All Logic to reset password or get username for user ----#
def verifyOTP(request):
    email = request.session.get("reset_email")  # Store email for later use
    
    if not email:
        messages.warning(request, "Please request for otp first!")
        return redirect("login")

    if request.method == "POST":
        user_otp = request.POST.get('otp')  # OTP entered by the user
        otp_sent = request.session.get('otp_sent')  # OTP stored in session
        otp_expiry = request.session.get('otp_expiry')  # OTP expiration time
        email = request.session.get("reset_email")  # Store email for later use
        request_type = request.session.get("request_type")  # Username or Password reset?

        # 🛑 Check if email is missing from session
        if not email:
            messages.error(request, "Session expired! Please try again.")
            return redirect("login")  # Redirect to OTP request page

        # 🛑 Check if OTP data is missing from session
        if not otp_sent or not otp_expiry:
            messages.error(request, "OTP expired or not found! Please request a new one.")
            return redirect('login')

        # ✅ Convert expiry time from string to datetime object
        expiry_time = datetime.strptime(otp_expiry, "%Y-%m-%d %H:%M:%S")

        # 🛑 Check if OTP is expired
        if datetime.now() > expiry_time:
            # Clear expired OTP session
            request.session.pop('otp_sent', None)
            request.session.pop('otp_expiry', None)
            request.session.modified = True
            messages.error(request, "OTP expired! please request again.")
            return redirect('login')  # Redirect user to request a new OTP

        # ✅ Check if OTP entered is correct
        if user_otp and str(otp_sent) == user_otp:
            user = User.objects.filter(email=email).first()

            # 🛑 Ensure user exists
            if not user:
                messages.error(request, "User not found!")
                return redirect("login")

            if request_type == "username":
                first_name = user.first_name
                last_name = user.last_name

                # Format full name properly
                full_name = f"{first_name} {last_name}".strip()  # Removes extra spaces if any field is empty

                # If the user doesn't have a first or last name, fallback to username
                if not full_name:
                    full_name = user.username

                # Website name (Customize this)
                WEBSITE_NAME = "🔷Mutual Fund Recommendation System"

                # Subject Line
                subject = f"{WEBSITE_NAME} 🔑 Username Recovery Request"

                # HTML Email Body
                message = f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                        <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px #ccc;">
                            <h2 style="color: #4CAF50; text-align: center;">🔐 Username Recovery Request</h2>
                            <p>Dear <strong>{full_name}</strong>,</p>
                            <p>You recently requested your username for our platform.</p>
                            <p><strong>Your username:</strong> <span style="color: #2c3e50; font-weight: bold;">{user.username}</span></p>
                            <p>If you did not request this, please ignore this email or contact support.</p>
                            <hr style="border: 0; height: 1px; background: #ddd;">
                            <p style="text-align: center; font-size: 12px; color: #555;">
                                This is an automated message from <strong>{WEBSITE_NAME}</strong>. Please do not reply.
                            </p>                        
                        </div>
                    </body>
                    </html>
                """
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [email]

                send_mail(
                    subject,
                    "",  # Empty text version since we're using HTML
                    from_email,
                    recipient_list,
                    html_message=message,  # Send as HTML email
                )

                messages.success(request, "Your username has been sent to your registered email!")
                return redirect("login")  # Redirect after success
            
            elif request_type == "password":
                messages.success(request, "✔ OTP verified successfully!")
                return redirect("resetpass")  # Redirect to password reset page
            
            else:
                messages.error(request, "Invalid request type.")
                return redirect("forgetpass")  # Redirect back to forgot password page
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect('verifyotp')

    # ✅ Render the OTP verification page
    context = {
        'title': 'Verify OTP',
        'header': 'Verify your OTP',
    }
    return render(request, 'VerifyOtp.html', context)

# Send otp on email for reset password for user
def forgetpassword(request):
    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')

        try:
            # Check if user exists
            user = User.objects.get(email=email, username=username)

            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)

            # Store OTP and expiry in session
            expiry_time = datetime.now() + timedelta(minutes=5)
            request.session['reset_email'] = email
            request.session['otp_sent'] = otp
            request.session['otp_expiry'] = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
            request.session["request_type"] = "password"  # Store request type
            request.session.modified = True  # Ensure session is updated

            # Get first name and last name
            first_name = user.first_name
            last_name = user.last_name

            # Format full name properly
            full_name = f"{first_name} {last_name}".strip()  # Removes extra spaces if any field is empty

            # If the user doesn't have a first or last name, fallback to username
            if not full_name:
                full_name = user.username

            # Website Name
            WEBSITE_NAME = "🔷 Mutual Fund Recommendation System"

            # Subject Line
            subject = f"{WEBSITE_NAME} 🔑 Your OTP to Reset Password"

            # HTML Email Body
            message = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px #ccc;">
                        <h2 style="color: #4CAF50; text-align: center;">🔐 OTP to Reset Password</h2>
                        <p>Dear <strong>{full_name}</strong>,</p>
                        <p>You recently requested to reset your password.</p>
                        <p><strong>Your One-Time Password (OTP):</strong> 
                            <span style="color: #2c3e50; font-weight: bold; font-size: 20px;">{otp}</span>
                        </p>
                        <p>Use this OTP to reset your password. This OTP is valid for a limited time.</p>
                        <p>If you did not request this, please ignore this email or contact support.</p>
                        <hr style="border: 0; height: 1px; background: #ddd;">
                        <p style="text-align: center; font-size: 12px; color: #555;">
                            This is an automated message from <strong>{WEBSITE_NAME}</strong>. Please do not reply.
                        </p>                        
                    </div>
                </body>
                </html>
            """

            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]

            send_mail(
                subject,
                "",  # Empty text version since we're using HTML
                from_email,
                recipient_list,
                html_message=message,  # Send as HTML email
            )
        
            messages.success(request, "OTP sent to your email successfully.")        
            return redirect('verifyotp')

        except User.DoesNotExist:
            messages.error(request, "Invalid username or email!")
            return redirect('forgetpass')
        
    context = {
        'title': 'Forgot Password',
        'header': 'Send OTP',
    }

    return render(request, 'Forgetpass.html', context)

# Route to handle reset password after verified otp
def resetpassword(request):
    email = request.session.get("reset_email")  # Store email for later use
    
    if not email:
        messages.warning(request, "Please verify with otp first!")
        return redirect("forgetpass")
    
    if request.method == "POST":
        password = request.POST.get("password")
        cpassword = request.POST.get("cpassword")
        email = request.session.get("reset_email")  # Retrieve email from session

        if not email:
            messages.error(request, "Session expired! Please restart the reset process.")
            return redirect("forgetpass")

        if len(password) < 6:
            messages.error(request, "Password is too short! Please use at least 6 characters.")
            return redirect("resetpass")

        if password != cpassword:
            messages.error(request, "Passwords do not match!")
            return redirect("resetpass")

        try:
            # Find the user by email
            user = User.objects.get(email=email)

            # Update password securely
            user.password = make_password(password)
            user.save()

            # Clear session variables after successful reset
            request.session.pop("reset_email", None)
            request.session.modified = True

            # Get user's full name or fallback to username
            full_name = f"{user.first_name} {user.last_name}".strip()
            if not full_name:
                full_name = user.username

            # Website Name
            WEBSITE_NAME = "🔷 Mutual Fund Recommendation System"

            # Email subject
            subject = f"{WEBSITE_NAME} 🔑 Password Reset Successful"

            # HTML Email Body
            message = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px #ccc;">
                        <h2 style="color: #4CAF50; text-align: center;">🔑 Password Reset Successful</h2>
                        <p>Dear <strong>{full_name}</strong>,</p>
                        <p>We are pleased to inform you that your password has been successfully reset for your <strong>{WEBSITE_NAME}</strong> account.</p>
                        <p><strong>Next Steps:</strong></p>
                        <ul>
                            <li>Use your new password to log in securely.</li>
                            <li>For security reasons, do not share your password with anyone.</li>
                            <li>If you did not request this password reset, please contact our support team immediately.</li>
                        </ul>
                        <p>We recommend updating your password regularly to keep your account secure.</p>
                        <p>If you have any issues, feel free to reach out to our support team.</p>
                        <hr style="border: 0; height: 1px; background: #ddd;">
                        <p style="text-align: center; font-size: 12px; color: #555;">
                            This is an automated message from <strong>{WEBSITE_NAME}</strong>. Please do not reply.
                        </p>                        
                    </div>
                </body>
                </html>
            """

            # Send confirmation email
            send_mail(
                subject,
                "",  # The plaintext version is not necessary since we are sending HTML
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
                html_message=message,  # HTML content
            )

            messages.success(request, "Password changed successfully! You can log in now.")
            return redirect("login")  # ✅ Redirect to login only after reset

        except User.DoesNotExist:
            messages.error(request, "User not found. Please try again.")
            return redirect("forgetpass")

    # ✅ Show reset password page only if OTP was verified
    return render(request, "Resetpass.html")

def forgetusername(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            # Check if user exists
            user = User.objects.get(email=email)

            # Generate a 6-digit OTP
            otp = random.randint(100000, 999999)

            # Store OTP and expiry in session
            expiry_time = datetime.now() + timedelta(minutes=2)
            request.session['reset_email'] = email
            request.session['otp_sent'] = otp
            request.session['otp_expiry'] = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
            request.session["request_type"] = "username"  # Store request type
            request.session.modified = True  # Ensure session is updated

            # Get first name and last name
            first_name = user.first_name
            last_name = user.last_name

            # Format full name properly
            full_name = f"{first_name} {last_name}".strip()  # Removes extra spaces if any field is empty

            # If the user doesn't have a first or last name, fallback to username
            if not full_name:
                full_name = user.username

            # Website Name
            WEBSITE_NAME = "🔷 Mutual Fund Recommendation System"

            # Subject Line
            subject = f"{WEBSITE_NAME} 🔑 OTP for Username Recovery"

            # HTML Email Body
            message = f"""
                <html>
                <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px #ccc;">
                        <h2 style="color: #4CAF50; text-align: center;">🔐 OTP to Recover Your Username</h2>
                        <p>Dear <strong>{full_name}</strong>,</p>
                        <p>You recently requested to recover your username.</p>
                        <p><strong>Your One-Time Password (OTP):</strong> 
                            <span style="color: #2c3e50; font-weight: bold; font-size: 20px;">{otp}</span>
                        </p>
                        <p>Use this OTP to verify your identity and proceed with username recovery.</p>
                        <p>If you did not request this, please ignore this email or contact support.</p>
                        <hr style="border: 0; height: 1px; background: #ddd;">
                        <p style="text-align: center; font-size: 12px; color: #555;">
                            This is an automated message from <strong>{WEBSITE_NAME}</strong>. Please do not reply.
                        </p>                        
                    </div>
                </body>
                </html>
            """

            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]

            send_mail(
                subject,
                "",  # Empty text version since we're using HTML
                from_email,
                recipient_list,
                html_message=message,  # Send as HTML email
            )
                    
            messages.success(request, "OTP sent to your email successfully!")        
            return redirect('verifyotp')

        except User.DoesNotExist:
            messages.error(request, "Invalid email! Please try again.")
            return redirect('forgetusername')
        
    context = {
        'title': 'Forget Username',
        'header': 'Send OTP',
    }
    return render(request,'Forgetusername.html', context)

# Add new user/ new user registration
def newuser(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('newpassword', '').strip()
        confirm_password = request.POST.get('confirmpassword', '').strip()

        # Validation Checks
        if not username or not email or not password or not confirm_password:
            messages.error(request, "All fields are required!")
            return redirect('newuser')

        if len(username) < 4:
            messages.error(request, "Username must be at least 4 characters long!")
            return redirect('newuser')

        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('newuser')

        if len(password) < 6:
            messages.error(request, "Password must be at least 6 characters long!")
            return redirect('newuser')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken!")
            return redirect('newuser')

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered!")
            return redirect('newuser')

        # Create new user
        user = User.objects.create(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=make_password(password),  # Hash the password before saving
            is_active=True
        )

        
        # Get first name and last name
        first_name = first_name
        last_name = last_name

        # Format full name properly
        full_name = f"{first_name} {last_name}".strip()  # Removes extra spaces if any field is empty

        # Website Name
        WEBSITE_NAME = "🔷 Mutual Fund Recommendation System"

        # Subject Line
        subject = f"{WEBSITE_NAME} 🔑 Your OTP to Reset Password"

        # HTML Email Body
        message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0px 0px 10px #ccc;">
                <h2 style="color: #4CAF50; text-align: center;">🎉 Congratulations! Registration Successful</h2>
                <p>Dear <strong>{full_name}</strong>,</p>
                <p>Welcome to <strong>{WEBSITE_NAME}</strong>! 🎊</p>
                <p>We are thrilled to have you on board. Your registration has been successfully completed, and you can now explore our platform to get personalized mutual fund recommendations.</p>
                <p><strong>Next Steps:</strong></p>
                <ul>
                    <li>Log in to your account and complete your profile.</li>
                    <li>Start exploring mutual fund recommendations tailored for you.</li>
                    <li>Stay updated with real-time market trends.</li>
                </ul>
                <p>If you have any questions, feel free to reach out to our support team.</p>
                <p>We look forward to helping you make informed investment decisions!</p>
                <hr style="border: 0; height: 1px; background: #ddd;">
                <p style="text-align: center; font-size: 12px; color: #555;">
                    This is an automated message from <strong>{WEBSITE_NAME}</strong>. Please do not reply.
                </p>                        
            </div>
        </body>
        </html>
        """

        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        send_mail(
            subject,
            "",  # Empty text version since we're using HTML
            from_email,
            recipient_list,
            html_message=message,  # Send as HTML email
        )

        messages.success(request, "User registered successfully! You can log in now.")
        return redirect('login')  # Redirect to login page after success
    
    context = {
        'title': 'New User Registration',
        'header': 'New User Registration',
    }
    return render(request, 'Newuser.html', context)

#---- All route to show about, services and contact page ---#

def about(request):
    context = {
        'title': 'About Us',
        'header': 'About Us',
    }
    return render(request,'About.html', context)

def services(request):
    context = {
        'title': 'Our Services',
        'header': 'Our Services',
    }
    return render(request,'Services.html', context)

def contact(request):
    context = {
        'title': 'Contact Us',
        'header': 'Contact Us',
    }
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        phone = request.POST['phone']
        message = request.POST['message']

        contact = Contact(name=name, email=email, phone=phone, message=message, date=datetime.now())
        contact.save()
        
        messages.success(request, f"Dear {name}, Your message has been sent successfully! we will get back to you soon.") 
        return redirect('contact')
    return render(request,'Contact.html', context)

@login_required
def account_settings(request):
    if request.method == "POST":
        formtype = request.POST.get("form_type")  # ✅ Prevents KeyError

        # ✅ Password Change Logic
        if formtype == "changepass":
            username = request.session.get("username")
            oldpass = request.POST.get("old_password")
            newpass = request.POST.get("new_password")
            confirmpass = request.POST.get("confirm_password")

            user = User.objects.filter(username=username).first()
            if not user:
                messages.error(request, "User not found!")
                return redirect("account_settings")

            if not check_password(oldpass, user.password):
                messages.error(request, "Invalid password! Please try again")
                return redirect("account_settings")

            if newpass != confirmpass:
                messages.error(request, "New password should match confirm password!")
                return redirect("account_settings")

            if len(newpass) < 6:
                messages.error(request, "Password must be ≥6 characters!")
                return redirect("account_settings")

            # ✅ Update password AND maintain session
            user.set_password(newpass)  # Uses Django's built-in method
            user.save()

            # ✅ Re-authenticate the user
            updated_user = authenticate(username=username, password=newpass)
            if updated_user:
                login(request, updated_user)  # Re-establish session
                messages.success(request, "Password changed successfully!")
            else:
                messages.error(request, "Session update failed. Please log in again.")

            return redirect("account_settings")  # Redirect back to settings
                
        elif formtype == "uploadpic":
            if "profile_picture" in request.FILES:
                user = request.user
                image = request.FILES["profile_picture"]

                print(f"DEBUG: File received - {image.name}")  # ✅ Debugging

                # Ensure the upload directory exists
                upload_dir = os.path.join(settings.MEDIA_ROOT, "profile_pics/")
                os.makedirs(upload_dir, exist_ok=True)

                # Generate unique filename
                image_filename = f"{user.username}_{image.name}"
                file_path = os.path.join("profile_pics/", image_filename)  # ✅ Relative to MEDIA_ROOT

                # Save the file
                saved_path = default_storage.save(file_path, image)
                print(f"DEBUG: File saved at {saved_path}")  # ✅ Debugging

                # Update profile picture in the database
                profile, created = ProfilePic.objects.get_or_create(username=user)

                # ✅ Delete the old file before saving the new one
                if profile.filename:
                    old_file_path = os.path.join(settings.MEDIA_ROOT, str(profile.filename))  # Convert to string if needed
                    try:
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                            print(f"DEBUG: Old file removed - {old_file_path}")  # ✅ Debugging
                    except Exception as e:
                        print(f"DEBUG: Error deleting old file - {e}")  # ❌ Debugging

                # Save new profile picture
                profile.filename = saved_path  # Save the new file path in the database
                profile.save()  # Ensure the updated profile is saved to the database
                print(f"DEBUG: Profile updated with new image - {saved_path}")  # ✅ Debugging

                messages.success(request, "Profile picture updated successfully!")
            else:
                print("DEBUG: No file received!")  # ❌ Debugging
                messages.error(request, "No file uploaded! Please select a file.")

            return redirect("/")  # Redirect to settings page

    context = {
        'title': 'Account Settings',
        'header': 'Account Settings',
    }
    return render(request, 'Settings.html', context)

# Delete account by user
@login_required
def delete_account(request):
    if request.method == "POST":
        user = request.user  # Get the currently logged-in user
        user.delete()  # Delete the user
        logout(request)  # Log out the user
        messages.success(request, "Your account has been deleted successfully.")
        return redirect("landing_page")  # Redirect to homepage or login page
    context = {
        'title': 'Delete Account',
        'header': 'Confirm Account Deletion'
    }
    return render(request, "Delete_account.html", context)

"""def upload_profile_picture(request):
    if request.method == "POST":
        if "profile_picture" in request.FILES:
            user = request.user
            image = request.FILES["profile_picture"]

            print(f"DEBUG: File received - {image.name}")  # ✅ Debugging

            # Ensure the upload directory exists
            upload_dir = os.path.join(settings.MEDIA_ROOT, "profile_pics/")
            os.makedirs(upload_dir, exist_ok=True)

            # Generate unique filename
            image_filename = f"{user.username}_{image.name}"
            file_path = os.path.join("profile_pics/", image_filename)  # ✅ Relative to MEDIA_ROOT

            # Save file
            saved_path = default_storage.save(file_path, image)
            print(f"DEBUG: File saved at {saved_path}")  # ✅ Debugging

            # Update profile picture in the database
            profile, created = ProfilePic.objects.get_or_create(username=user)
            profile.filename = saved_path
            profile.save()

            messages.success(request, "Profile picture updated successfully!")
        else:
            print("DEBUG: No file received!")  # ❌ Debugging
            messages.error(request, "No file uploaded! Please select a file.")

        return redirect("account_settings")  # Redirect to settings page
"""