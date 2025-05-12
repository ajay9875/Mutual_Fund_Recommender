from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.utils.timezone import now
from django.utils import timezone
from django.core.mail import send_mail
from django.http import HttpResponseServerError
from Myapp.models import Contact
from .models import ProfilePic
import os
import random
from datetime import datetime, timedelta
from .models import Task
from decouple import config

import requests
#from dotenv import load_dotenv
#load_dotenv() 

from django.http import HttpResponse
from .notifications import send_daily_notifications

def run_daily(request):
    send_daily_notifications()
    return HttpResponse("Daily notifications sent successfully!.")

def task_list(request):
    tasks = Task.objects.all()
    return render(request, 'task_list.html', {'tasks': tasks})

def my_view(request):
    try:
        # Some code that might raise an exception
        raise ValueError("Something went wrong!")
    except ValueError:
        # Trigger a custom 500 error page
        return HttpResponseServerError(render(request, "404.html"))

def default(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('landing_page')
    
# Landing / Home page rendering for not logged in user(Redirect to dashboard if logged in user found)
def landing_page(request):
    return render(request,'Default.html')

"""
from django.http import JsonResponse

# Fetching NAV data from AMFI API
import requests

from django.http import JsonResponse
from django.shortcuts import render
import requests
from django.views.decorators.csrf import csrf_exempt

# Function to fetch NAV data from AMFI
from django.http import JsonResponse
import requests

# Function to fetch NAV data from AMFI
def fetch_amfi_nav_data():
    url = "https://www.amfiindia.com/spages/NAVAll.txt"
    response = requests.get(url)

    if response.status_code != 200:
        return []

    lines = response.text.splitlines()
    funds = []

    for line in lines:
        if line.strip() and line[0].isdigit():
            parts = line.split(";")
            if len(parts) == 6:
                funds.append({
                    "scheme_code": parts[0],
                    "isin": parts[1],
                    "scheme_name": parts[3],
                    "nav": parts[4],
                    "date": parts[5]
                })
    return funds

# View to get NAV data for a specific scheme
def nav_data_api(request):
    scheme = request.GET.get('scheme')
    if not scheme:
        return JsonResponse({"error": "Scheme parameter is missing"}, status=400)
    
    # Fetch data from AMFI
    data = fetch_amfi_nav_data()

    # Filter the data based on the provided scheme name (case-insensitive)
    filtered = [d for d in data if scheme.lower() in d["scheme_name"].lower()]

    if not filtered:
        return JsonResponse({"error": f"No NAV data found for scheme: {scheme}"}, status=404)

    # Group by date and get the most recent NAV for each date
    date_to_nav = {}
    for entry in filtered:
        if entry["date"] not in date_to_nav:
            date_to_nav[entry["date"]] = []
        date_to_nav[entry["date"]].append(float(entry["nav"]))

    # Get the most recent 30 entries
    dates = list(date_to_nav.keys())[-30:]
    navs = [max(nav_list) for nav_list in date_to_nav.values()][-30:]

    return JsonResponse({
        "dates": dates,
        "navs": navs
    })

# Example CSRF-exempt view for fetching NAV data history
@csrf_exempt
def nav_data_view(request):
    scheme = request.GET.get('scheme')
    if not scheme:
        return JsonResponse({'error': 'Scheme parameter is missing'}, status=400)

    # Example logic to fetch NAV data (replace with actual logic)
    nav_history = fetch_nav_history_for_scheme(scheme)  # This should return a list of dicts with 'date' and 'nav'

    return JsonResponse(nav_history, safe=False)

def fetch_nav_history_for_scheme(scheme):
    # Fetch the NAV data from AMFI
    data = fetch_amfi_nav_data()

    # Filter the data based on the provided scheme name (case-insensitive)
    filtered = [d for d in data if scheme.lower() in d["scheme_name"].lower()]

    # If no matching data is found, return an empty list
    if not filtered:
        return []

    # Return the filtered data with 'date' and 'nav' as a list of dictionaries
    nav_history = [{"date": entry["date"], "nav": float(entry["nav"])} for entry in filtered]
    
    return nav_history"""

import requests
from django.shortcuts import render
from django.http import JsonResponse
from decouple import config
# List of all available exact fund names
fund_list = [
    "Axis Nifty Midcap 50 Index Fund Regular Growth",
    "Aditya Birla Sun Life Nifty Midcap 150 Index Fund Regular Growth",
    "SBI Small Cap Fund Regular Growth",
    "ICICI Prudential Bluechip Fund Regular Growth",
    # Add more as needed
]

API_KEY = config("API_ACCESS_KEY")

"""# Fuzzy matching using fuzzywuzzy/thefuzz
def find_best_match(user_input):

    # Get the best match from the list
    best_match, score = process.extractOne(user_input, fund_list)

    # Threshold to ensure it's a reasonable match (optional)
    if score >= 80:
        print("Best match found:", best_match)
        return best_match
    else:
        print("No reliable match found.")
        return None"""

def get_single_fund_data_by_api(fund_name):
    url = "https://stock.indianapi.in/mutual_funds_details"
    querystring = {"stock_name": fund_name}
    headers = {"X-Api-Key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()  # Raises HTTPError for bad responses
        return response.json()

    except requests.exceptions.RequestException:
        return None
    
# To show specific fund details using fund name
@never_cache
def fund_details(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('landing_page')

    context = {}  # Always define context to avoid UnboundLocalError

    if request.method == "POST":
        fund_name = request.POST.get('fund_name')  # Use .get() for safety
       
        if fund_name:
            #best_matched_name = find_best_match(fund_name)
            #print(f"Fund name received: {best_matched_name}")
            fund_data = get_single_fund_data_by_api(fund_name)

            if fund_data and fund_data.get('basic_info', {}).get('fund_name'):
                processed_fund = {
                    'fund_name': fund_data.get('basic_info', {}).get('fund_name', None),
                    'category': fund_data.get('basic_info', {}).get('category', None),
                    'risk_level': fund_data.get('basic_info', {}).get('risk_level', None),
                    'plan_type': fund_data.get('basic_info', {}).get('plan_type', None),
                    'scheme_type': fund_data.get('basic_info', {}).get('scheme_type', None),
                    'inception_date': fund_data.get('basic_info', {}).get('inception_date', None),
                    'benchmark': fund_data.get('basic_info', {}).get('benchmark', 'NA'),
                    'benchmark_name': fund_data.get('basic_info', {}).get('benchmark_name', None),
                    'fund_size': fund_data.get('basic_info', {}).get('fund_size', None),
                    'fund_manager': fund_data.get('basic_info', {}).get('fund_manager', None),
                    'registrar_agent': fund_data.get('basic_info', {}).get('registrar_agent', None),

                    'current_nav': fund_data.get('nav_info', {}).get('current_nav', None),
                    'nav_date': fund_data.get('nav_info', {}).get('nav_date', None),

                    'absolute_returns': fund_data.get('returns', {}).get('absolute', {}),
                    'cagr': fund_data.get('returns', {}).get('cagr', {}),
                    'category_returns': fund_data.get('returns', {}).get('category_returns', {}),
                    'index_returns': fund_data.get('returns', {}).get('index_returns', {}),

                    'risk_metrics': fund_data.get('returns', {}).get('risk_metrics', {}),
                    'expense_ratio': fund_data.get('expense_ratio', {}).get('current', None),
                    'expense_history': fund_data.get('expense_ratio', {}).get('history', []),

                    'debug': True,
                    'all_data': fund_data,
                }

                context = {
                    'fund_data': fund_data,
                    'fund_name': processed_fund['fund_name'],
                    'category': processed_fund['category'],
                    'risk_level': processed_fund['risk_level'],
                    'plan_type': processed_fund['plan_type'],
                    'scheme_type': processed_fund['scheme_type'],
                    'inception_date': processed_fund['inception_date'],
                    'benchmark': processed_fund['benchmark'],
                    'benchmark_name': processed_fund['benchmark_name'],
                    'fund_size': processed_fund['fund_size'],
                    'fund_manager': processed_fund['fund_manager'],
                    'registrar_agent': processed_fund['registrar_agent'],

                    'current_nav': processed_fund['current_nav'],
                    'nav_date': processed_fund['nav_date'],

                    'absolute_returns': processed_fund['absolute_returns'],
                    'cagr': processed_fund['cagr'],
                    'category_returns': processed_fund['category_returns'],
                    'index_returns': processed_fund['index_returns'],

                    'risk_metrics': processed_fund['risk_metrics'],
                    'expense_ratio': processed_fund['expense_ratio'],
                    'expense_history': processed_fund['expense_history'],

                    'debug': processed_fund['debug'],
                    'all_data': processed_fund['all_data'],
                }
                messages.success(request, "Fund details fetched successfully!")
                return render(request, 'Fund_details.html', context)

            else:
                messages.warning(request, "Fund information is currently unavailable. Please try again later.")
                return redirect('fund_details')
        else:
            messages.info(request, "Please input fund name first!")
            return redirect('fund_details')

    return render(request, 'Fund_details.html')

#It's for all fund data using fund type
def get_all_funds_data_by_indian_api(fund_type):
    # URL for fetching mutual funds data
    url = "https://stock.indianapi.in/mutual_funds"
    
    # Headers to pass the API key
    headers = {"X-Api-Key": API_KEY}

    # Add the fund_type as a query parameter to filter data
    params = {
        "fund_type": fund_type  # Assuming the API supports filtering by fund type
    }

    # Send GET request with the headers and params
    response = requests.get(url, headers=headers, params=params)

    # Return the JSON response if the request is successful
    if response.status_code == 200:
        return response.json()
    else:
        return []

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

    recommended_funds = []

    if request.method == "POST":
        fund_type = request.POST["company_type"]
 
        if fund_type == "manually":
            fund_type = request.POST["manual_company_type"]
        
        if fund_type:
            raw_fund_data = get_all_funds_data_by_indian_api(fund_type)

            # Flatten and process nested structure
            for main_category, subtypes in raw_fund_data.items():
                for subtype, funds in subtypes.items():
                    if main_category == fund_type or subtype == fund_type:
                        for fund in funds:
                            processed = {
                                'fund_name': fund.get('fund_name', None),
                                'investment_type': main_category,
                                'category': subtype,
                                'latest_nav': fund.get('latest_nav', None),
                                'star_rating': fund.get('star_rating', None),
                                'return_rate': (
                                    fund.get('5_year_return')
                                    or fund.get('3_year_return')
                                    or fund.get('1_year_return')
                                    or 'N/A'
                                ),
                                'duration': (
                                    '5 years' if fund.get('5_year_return') else
                                    '3 years' if fund.get('3_year_return') else
                                    '1 year'
                                )
                            }
                            recommended_funds.append(processed)
        else:
            raw_fund_data = get_all_funds_data_by_indian_api(fund_type)
            # Flatten and process nested structure
            for main_category, subtypes in raw_fund_data.items():
                for subtype, funds in subtypes.items():
                    #if main_category == fund_type or subtype == fund_type:
                    for fund in funds:
                        processed = {
                            'fund_name': fund.get('fund_name', None),
                            'investment_type': main_category,
                            'category': subtype,
                            'latest_nav': fund.get('latest_nav', None),
                            'star_rating': fund.get('star_rating', None),
                            'return_rate': (
                                fund.get('5_year_return')
                                or fund.get('3_year_return')
                                or fund.get('1_year_return')
                                or 'N/A'
                            ),
                            'duration': (
                                '5 years' if fund.get('5_year_return') else
                                '3 years' if fund.get('3_year_return') else
                                '1 year'
                            )
                        }
                        recommended_funds.append(processed)

        """
        fund = get_fund_data_by_api(fund_type)
        if fund:
            try:
                processed = {
                    'fund_name': fund['basic_info']['fund_name'],
                    'category': fund['basic_info']['category'],
                    'risk': fund['basic_info']['risk_level'],
                    'return_rate': fund['returns']['cagr'].get('5y', 'N/A'),  # or any time period
                    'investment_type': fund['basic_info']['scheme_type'],
                    'duration': "5 years",  # You can adjust this logic
                }
                recommended_funds.append(processed)
            except KeyError as e:
                messages.error(request, f"Data is not present.")
                # Optionally log the error for debugging
                # app.logger.error(f"KeyError processing fund data: {str(e)} - Raw data: {raw_data}")
                
            except Exception as e:
                messages.error(request, "An error occurred while processing fund data.")
                # app.logger.error(f"Unexpected error processing fund: {str(e)} - Raw data: {raw_data}")"""
        
    context = {
        "remaining_time": remaining_time,
        "full_name": full_name,
        "profilepic": profilepic,  # Pass profile picture URL
        "recommended_funds": recommended_funds,
        "MEDIA_URL": settings.MEDIA_URL,  # Pass MEDIA_URL explicitly
    }
    return render(request, 'Index.html', context)

# To calculate sip
def sip_calculator(request):
    if request.method == 'POST':
        try:
            monthly_investment = float(request.POST.get('monthly_investment'))
            investment_duration = int(request.POST.get('investment_duration'))
            annual_return = float(request.POST.get('annual_return'))

            r = annual_return / 12 / 100  # monthly interest rate
            n = investment_duration * 12  # total months

            fv = monthly_investment * (((1 + r) ** n - 1) / r) * (1 + r)
            fv = round(fv)
            invested = round(monthly_investment * n)
            gain = round(fv - invested)

            context = {
                'monthly_investment': monthly_investment,
                'investment_duration': investment_duration,
                'annual_return': annual_return,
                'future_value': fv,
                'invested_amount': invested,
                'gain': gain,
                'calculated': True,
            }
        except Exception as e:
            context = {'error': "Invalid input. Please check your values."}
    else:
        context = {}

    return render(request, 'Sip_calculator.html', context)

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
            messages.success(request, "Login successful!")
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
        subject = f"{WEBSITE_NAME} 🎉Registration Successful!"

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
    

    return render(request, 'Newuser.html')

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
        
        messages.success(request, f"Dear {name}, thank you for reaching out to us! We have received your message and will get back to you shortly.") 
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
