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
from decouple import config
from Myapp.models import MutualFund


import requests
#from dotenv import load_dotenv
#load_dotenv() 

from django.http import HttpResponse
from .notifications import send_daily_notifications

def run_daily(request):
    send_daily_notifications()
    return HttpResponse("Daily notifications sent successfully!.")

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

#By IndianAPI.in
API_KEY = config("API_ACCESS_KEY")
#At Rapidapi by indian market api
#API_AUTH_TOKEN = config("API_AUTH_TOKEN")

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

#It's for all fund data using fund type
def get_all_funds_data_by_indian_api():
    # URL for fetching mutual funds data
    url = "https://stock.indianapi.in/mutual_funds"
    
    # Headers to pass the API key
    headers = {"X-Api-Key": API_KEY}

    """# Add the fund_type as a query parameter to filter data
        params = {
            "fund_type": fund_type  # Assuming the API supports filtering by fund type
        }"""

    # Send GET request with the headers and params
    response = requests.get(url, headers=headers)

    # Return the JSON response if the request is successful
    if response.status_code == 200:
        return response.json()
    else:
        return []

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
def fund_result(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('login')
    
    context = {}
    if request.method == "POST":
        fund_name = request.POST.get('fund_name')
        if fund_name:
            raw_fund_data = get_all_funds_data_by_indian_api()
            found_fund = None
            found_category = None
            found_subtype = None

            # Search through all categories
            for main_category, subtypes in raw_fund_data.items():
                for subtype, funds in subtypes.items():
                    for fund in funds:
                        if fund.get('fund_name') == fund_name:
                            found_fund = fund
                            found_category = main_category
                            found_subtype = subtype
                            break  # Found our fund, exit loops
                    if found_fund:
                        break
                if found_fund:
                    break

            if found_fund:
                context = {
                    'plan_type': found_category,
                    'scheme_type': found_subtype,
                    'fund': found_fund,  # Wrap in a list to maintain template structure
                }

                messages.success(request, "Mutual Fund data fetched successfully.")
            else:
                messages.error(request, f"Fund '{fund_name}' not found.")
                context = {'fund': None}

            return render(request, 'Fund_result.html', context)
    
    raw_fund_data = get_all_funds_data_by_indian_api()
    categorized_funds = []
    
    # Organize funds by category and scheme type
    for main_category, subtypes in raw_fund_data.items():
        for subtype, funds in subtypes.items():
            for fund in funds:
                categorized_funds.append({
                    'fund_name': fund.get('fund_name'),
                    'latest_nav': fund.get('latest_nav'),
                    'percentage_change': fund.get('percentage_change'),
                    'asset_size': fund.get('asset_size'),
                    '1_month_return': fund.get('1_month_return'),
                    '3_month_return': fund.get('3_month_return'),
                    '6_month_return': fund.get('6_month_return'),
                    '1_year_return': fund.get('1_year_return'),
                    '3_year_return': fund.get('3_year_return'),
                    '5_year_return': fund.get('5_year_return'),
                    'star_rating': fund.get('star_rating'),
                    'investment_type': main_category,  # Debt/Equity/etc
                    'category': subtype  # Floating Rate/Dynamic Bond/etc
                })

    context = {
        'categorized_funds': categorized_funds,
        'show_table': True
    }

    # Default return for GET requests or invalid POST
    return render(request, 'Fund_result.html', context)
    
@never_cache
def fund_details(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('login')

    context = {}

    if request.method == "POST":
        fund_name = request.POST.get('fund_name').strip()
        if not fund_name:
            messages.error(request, "Fund name is missing.")
            return redirect('fund_details')

        fund_data = get_single_fund_data_by_api(fund_name)
        if fund_data:
            try:
                basic_info = fund_data.get('basic_info', {})
                name_of_fund = basic_info.get('fund_name')
                if not name_of_fund:
                    raise ValueError("Fund data not found, please try again.")
                    
                returns = fund_data.get('returns', {})
                expense_ratio = fund_data.get('expense_ratio', {})
                context = {
                    'basic_info': fund_data.get('basic_info', {}),
                    'nav_info': fund_data.get('nav_info', {}),
                    'absolute_returns': returns.get('absolute', {}),
                    'cagr_returns': returns.get('cagr', {}),
                    'category_returns': returns.get('category_returns', {}),
                    'index_returns': returns.get('index_returns', {}),
                    'risk_metrics': returns.get('risk_metrics', {}),
                    'exit_load': fund_data.get('exit_load', []),
                    'investment_info': fund_data.get('investment_info', {}),
                    'fund_house_info': fund_data.get('fund_house', {}),
                    'additional_info': fund_data.get('additional_info', {}),
                    'holdings': fund_data.get('holdings', []),
                    'current_expense_ratio': expense_ratio.get('current', "NA"),
                    'expense_ratio_history': expense_ratio.get('history', []),
                }

                messages.success(request, "Mutual Fund data fetched successfully.")
                return render(request, 'Fund_details.html', context)
            except ValueError as e:
                messages.error(request, str(e))

    # Always return at least empty context
    return render(request, 'Fund_details.html', context)

@never_cache
def userdashboard(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('login')

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
            raw_fund_data = get_all_funds_data_by_indian_api()

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
            raw_fund_data = get_all_funds_data_by_indian_api()
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
        
    context = {
        "remaining_time": remaining_time,
        "full_name": full_name,
        "profilepic": profilepic,  # Pass profile picture URL
        "recommended_funds": recommended_funds,
        "MEDIA_URL": settings.MEDIA_URL,  # Pass MEDIA_URL explicitly
    }
    return render(request, 'Index.html', context)

@never_cache
def your_funds(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('landing_page')
    
    username = request.session.get('username', '')

    if request.method == "POST":
        form_type = request.POST['form_type']
        
        if form_type == "delete-fund":
            try:
                fund_name = request.POST['fund_name']
                if fund_name:
                    fund = MutualFund.objects.get(username=username, fund_name=fund_name)
                    fund.delete()
                    messages.success(request, f"The fund '{fund_name}' has been deleted.")
                    return redirect('your_funds')
            except MutualFund.DoesNotExist:
                messages.error(request, "Fund not found or already deleted.")
                return redirect('your_funds')
            
        elif form_type == "add-fund":
            fund_name = request.POST['fund_name']
            investment_type = request.POST['investment_type']
            subcategory = request.POST['subcategory']
            if not fund_name or not investment_type or not subcategory:
                messages.error(request, "All fields are required.")
                return redirect('your_funds')
            
            existing_fund = MutualFund.objects.filter(username=username, fund_name=fund_name)
            if existing_fund:
                messages.error(request, "Looks like this fund is already added, no need to do it twice!")
                return redirect('dashboard')

            fund_data = MutualFund.objects.create(
                        username=username,
                        fund_name=fund_name,
                        investment_type=investment_type,
                        subcategory=subcategory
                        )
            fund_data.save()
            messages.success(request, " Your fund details have been saved with care and precision.")
            return redirect('dashboard')

    try:
        if username:
            fund_details = MutualFund.objects.filter(username=username)

    except Exception as e:
        messages.error(request, "Unable to fetch your fund right now!")

    return render(request, 'Your_funds.html', {'fund_details':fund_details})

# Calculate sip
def sip_calculator(request):
    if request.method != 'POST':
        return render(request, 'Sip_calculator.html')
    
    try:
        # Get and validate inputs
        monthly_investment = float(request.POST.get('monthly_investment', 0))
        investment_duration = int(request.POST.get('investment_duration', 0))
        annual_return = float(request.POST.get('annual_return', 0))
        
        # Input validation with immediate returns on error
        MAX_MONTHLY_INVESTMENT = 100000000  # 10 crore
        MAX_DURATION = 80  # 80 years
        MAX_RETURN = 100  # 100%
        
        if monthly_investment <= 0:
            raise ValueError("Monthly investment must be positive")
        if monthly_investment > MAX_MONTHLY_INVESTMENT:
            messages.error(request, f"Monthly investment cannot exceed ₹{MAX_MONTHLY_INVESTMENT:,}")
            return render(request, 'Sip_calculator.html', {'error': True})
        
        if investment_duration <= 0:
            messages.error(request, "Investment duration must be positive")
            return render(request, 'Sip_calculator.html', {'error': True})
        if investment_duration > MAX_DURATION:
            messages.error(request, f"Investment duration cannot exceed {MAX_DURATION} years")
            return render(request, 'Sip_calculator.html', {'error': True})
        
        if annual_return <= 0:
            messages.error(request, "Expected return must be positive")
            return render(request, 'Sip_calculator.html', {'error': True})
        if annual_return > MAX_RETURN:
            messages.error(request, f"Expected return cannot exceed {MAX_RETURN}%")
            return render(request, 'Sip_calculator.html', {'error': True})

        # Calculation (only reaches here if all validations pass)
        r = annual_return / 12 / 100  # monthly interest rate
        n = investment_duration * 12  # total months

        fv = monthly_investment * (((1 + r) ** n - 1) / r) * (1 + r)
        
        return render(request, 'Sip_calculator.html', {
            'monthly_investment': round(monthly_investment),
            'investment_duration': investment_duration,
            'annual_return': round(annual_return),
            'future_value': round(fv),
            'invested_amount': round(monthly_investment * n),
            'gain': round(fv - monthly_investment * n),
            'calculated': True,
        })

    except ValueError as e:
        messages.error(request, str(e))
        return render(request, 'Sip_calculator.html', {'error': True})
    except Exception as e:
        messages.error(request, "Invalid input format. Please enter numeric values")
        return render(request, 'Sip_calculator.html', {'error': True})

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

# All recoomendation is working properly
def userdashboard(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('login')

    if 'session_expiry' not in request.session:
        request.session['session_expiry'] = request.session.get_expiry_date().timestamp()

    expiry_time = request.session['session_expiry']
    current_time = datetime.now().timestamp()
    remaining_time = max(0, int(expiry_time - current_time))

    full_name = request.session.get('full_name', '').upper().strip()
    username = request.session.get('username', '').strip()
    # Check if the user has a ProfilePic object and fetch the filename
    
    try:
        profilepic = ProfilePic.objects.get(username=request.user).filename.url
    except ProfilePic.DoesNotExist:
        profilepic = None  # No profile picture found

    if not full_name:
        full_name = username

    # Initial context
    context = {
        "remaining_time": remaining_time,
        "full_name": full_name,
        "profilepic": profilepic,
        "recommended_funds": [],
        "form_data": {},
        "MEDIA_URL": settings.MEDIA_URL
    }
    #cache.delete('all_funds_data_to_recommend')
    # Handle POST submission
    if request.method == "POST":
        # Extract and normalize form data with default values for missing fields
        fund_type = request.POST.get("fund_type").strip()
        if fund_type.lower() == "manually":
            fund_type = request.POST.get("manual_company_type").strip()
        
        fund_subtype = request.POST.get("fund_subtype").strip()
        investment_tenure = request.POST.get("tenure").strip()
        return_type = request.POST.get("return_type").strip()

        #profit_percentage = request.POST.get("profit_percentage", "")
        #if profit_percentage.lower() == "other":
        #    profit_percentage = request.POST.get("custom_profit", "")
        """
        # Print all form values
        print("\n=== FORM VALUES ===")
        print(f"Fund Type (Original): {request.POST.get('company_type', 'Not provided')}")
        print(f"Fund Type (Processed): {fund_type}")
        #print(f"Risk Level: {risk}")
        print(f"Investment Tenure: {tenure}")
        print(f"Investment Type: {fund_subtype}")
        print(f"Return Type: {return_type}")
        #print(f"Expected Return (Original): {request.POST.get('profit_percentage', 'Not provided')}")
        #print(f"Expected Return: {profit_percentage}")
        """
        # Reassemble form data for rendering
        form_data = {
            "fund_type": fund_type,
            "fund_subtype": fund_subtype,
            "tenure": investment_tenure,
            "return_type": return_type,
        }

        context['form_data'] = form_data
        
        print(form_data)

        try:
            # Get fund data with special case flag
            raw_fund_data, is_special_case = get_funds_data_from_api(form_data)
            
            if raw_fund_data:
                print(f"Successfully fetched {len(raw_fund_data)} funds")
                
                if is_special_case is not None:
                    # Case 1: Special case (no filters or empty categories)
                    print("Displaying all funds (no filters applied)")
                    context["recommended_funds"] = raw_fund_data
                    messages.success(request, f"{len(raw_fund_data)} funds fetched successfully.")
                
                elif is_special_case is None:
                    # Case 2: Normal filtered case
                    print(f"Processing {len(raw_fund_data)} filtered funds")
                    recommended_funds = process_recommendations(form_data, raw_fund_data)
                    
                    if recommended_funds:
                        messages.success(request, f"{len(recommended_funds)} funds recommended successfully.")
                        context["recommended_funds"] = recommended_funds
                    else:
                        # Fallback to showing filtered results if no recommendations
                        messages.info(request, "No recommendations available for specific fund.")
            else:
                messages.error(request, "Could not fetch fund data.")

        except Exception as e:
            print(f"Recommendation processing error: {e}")
            messages.error(request, "System error during processing")

    return render(request, 'Index.html', context)
   
def get_funds_data_from_api(form_data):
    print(form_data)
    tenure = form_data.get('tenure', None)
    fund_type = form_data.get('fund_type', None)
    fund_subtype = form_data.get('fund_subtype', None)
    current_time = time.time()

    # Try getting from Django cache
    cached_data = cache.get('all_funds_data_to_recommend')
    last_fetched_time = cache.get('last_fetched_time', 0)

    print(f"LAST_FETCHED_TIME: {last_fetched_time}")
    print(f"CACHE_DURATION: {CACHE_DURATION}")
    print(f"Time since last fetch: {current_time - last_fetched_time}")

    if cached_data is not None and (current_time - last_fetched_time) < CACHE_DURATION and len(cached_data) > 1:
        print("Fetching cached data from django...")
        api_response = cached_data
        print("✅ Using cached fund data.")
    else:
        print("Fetching fresh data from API...")
        api_response = get_all_funds_data_by_indian_api()
        if api_response:
            # Save to Django cache
            cache.set('all_funds_data_to_recommend', api_response, timeout=CACHE_DURATION)
            cache.set('last_fetched_time', current_time, timeout=CACHE_DURATION)

        print(f"✅ Fetched and cached new data.")

    # Handle case where both filters are None
    if fund_type in [None, ''] and fund_subtype in [None, '']:
        processed_data = []
        for category, funds_data in api_response.items():
            if not isinstance(funds_data, dict):
                continue
            for sub_category, fund_list in funds_data.items():
                if not isinstance(fund_list, list):
                    continue
                for fund_item in fund_list:
                    try:
                        processed_data.append({
                            'fund_name': fund_item.get('fund_name', '').strip(),
                            'nav': round(float(fund_item.get('latest_nav')), 2),
                            'category': str(category) if category else "",
                            'sub_category': str(sub_category) if sub_category else "",
                            '1_month_return': float_or_none(fund_item.get('1_month_return')),
                            '3_month_return': float_or_none(fund_item.get('3_month_return')),
                            '6_month_return': float_or_none(fund_item.get('6_month_return')),
                            '1_year_return': float_or_none(fund_item.get('1_year_return')),
                            '3_year_return': float_or_none(fund_item.get('3_year_return')),
                            '5_year_return': float_or_none(fund_item.get('5_year_return')),
                            'asset_size': float_or_none(fund_item.get('asset_size')),
                            'star_rating': float_or_none(fund_item.get('star_rating')),
                            'return_type': estimate_return_type_using_tenure(tenure, fund_item.get(tenure)),
                            'risk': estimate_risk_from_return_profile(fund_item),
                            'is_special_case': True  # Mark special case funds
                        })
                    except Exception as e:
                        print(f"Error processing fund: {str(e)}")
                        continue
        print(f"Successfully processed {len(processed_data)} funds (special case)")
        return processed_data, "10"
    
    try:  
        if not api_response or not isinstance(api_response, dict):
            print("API returned empty or invalid response")
            return []

        #print(f"API contains categories: {list(api_response.keys())}")
        processed_data = []

        for category, funds_data in api_response.items():
            
            # Skip if funds_data is not a dict
            if not isinstance(funds_data, dict):
                #print(f"  Invalid funds data structure in {category}")
                continue

            # Process each sub-category in this category
            for sub_category, fund_list in funds_data.items():
                if not isinstance(fund_list, list):
                    #print(f"Skipping invalid sub-category {sub_category}")
                    continue
                
                if (category is not None and category ==  fund_type) or (sub_category is not None and sub_category == fund_subtype):
                    #print(f"Processing sub-category: {sub_category}")
                    for fund_item in fund_list:
                        try:
                            if not isinstance(fund_item, dict):
                                #print(f"    Skipping invalid fund data structure")
                                continue
                            
                            processed_data.append({
                                'fund_name': fund_item.get('fund_name', '').strip(),  # Rename to expected key
                                'nav': round(float(fund_item.get('latest_nav')), 2),
                                'category': category,
                                'sub_category': sub_category,
                                '1_month_return': float_or_none(fund_item.get('1_month_return')),
                                '3_month_return': float_or_none(fund_item.get('3_month_return')),
                                '6_month_return': float_or_none(fund_item.get('6_month_return')),

                                '1_year_return': float_or_none(fund_item.get('1_year_return')),
                                '3_year_return': float_or_none(fund_item.get('3_year_return')),
                                '5_year_return': float_or_none(fund_item.get('5_year_return')),
                                'asset_size': float_or_none(fund_item.get('asset_size')),
                                'star_rating': float_or_none(fund_item.get('star_rating')),
                                'return_type': estimate_return_type_using_tenure(tenure, fund_item.get(tenure, '1_year_return')),
                                'risk': estimate_risk_from_return_profile(fund_item),  # Optional: ensure risk is included
                            })
        
                        except Exception as e:
                            print(f"Error processing fund: {str(e)}")
                            continue

        print(f"Successfully processed {len(processed_data)} funds in category: {fund_type or 'All'}")
        return processed_data, None
        
    except Exception as e:
        print(f"Critical error: {str(e)}")
        return [], False

from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer

def process_recommendations(form_data, all_funds):
    if not all_funds or not form_data:
        print("Error: No fund data or form data provided.")
        return []

    try:
        # Extract filter parameters (case-insensitive)
        tenure = form_data.get('tenure', '1_year_return').strip()
        return_type = form_data.get('return_type').strip().lower()  # high/medium/low/negative

        # No need to filter by fund_type/subtype here - already done in get_funds_data_from_api()
        final_funds = []
        for fund in all_funds:
            # Get return value for the selected tenure
            fund_return = float_or_none(fund.get(tenure))
            if fund_return is None:
                continue

            # Classify return type
            classified_return = estimate_return_type_using_tenure(tenure, fund_return).lower()
            
            # Skip if return type doesn't match (when specified)
            if return_type and classified_return != return_type:
                continue

            final_funds.append({
                **fund,
                'return_value': fund_return,
                'return_class': classified_return
            })

        if not final_funds:
            print(f"No funds match the return type criteria: {return_type or 'Any'}")
            return []

        # Prepare data for similarity scoring
        texts, return_values = [], []
        for fund in final_funds:
            # Use fund characteristics for similarity
            combined_text = ' '.join([
                str(fund.get('fund_name', '')).lower(),
                str(fund.get('category', '')).lower(),
                str(fund.get('sub_category', '')).lower(),
                str(fund.get('return_class', '')).lower()
            ])
            texts.append(combined_text)
            return_values.append([fund['return_value']])

        # TF-IDF and scaling
        tfidf = TfidfVectorizer()
        tfidf_matrix = tfidf.fit_transform(texts)
        
        scaler = MinMaxScaler()
        numeric_features = scaler.fit_transform(return_values)
        
        # Combine features
        full_feature_matrix = np.hstack([tfidf_matrix.toarray(), numeric_features])

        # User query features
        user_text = ' '.join([
            form_data.get('fund_type', '').lower(),
            form_data.get('fund_subtype', '').lower(),
            return_type
        ]).strip()

        user_tfidf = tfidf.transform([user_text])
        user_numeric = scaler.transform([[np.median(return_values) if return_values else 0]])
        user_vector = np.hstack([user_tfidf.toarray(), user_numeric])

        # Calculate similarity
        similarities = cosine_similarity(user_vector, full_feature_matrix)[0]

        # Get top matches (lower threshold since we pre-filtered)
        matched_funds = []
        for idx, sim_score in enumerate(similarities):
            if sim_score >= 0.01:  # Lower threshold since we already filtered
                fund = final_funds[idx]
                fund['similarity'] = round(sim_score, 4)
                matched_funds.append(fund)

        # Return sorted results (max 10)
        matched_funds.sort(key=lambda x: x['similarity'], reverse=True)
        return matched_funds[:10]

    except Exception as e:
        print(f"Error in process_recommendations: {str(e)}")
        return []
    