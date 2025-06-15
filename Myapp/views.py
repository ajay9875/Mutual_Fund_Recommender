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
from django.core.cache import cache
import os
import random
from datetime import datetime, timedelta
from decouple import config
from Myapp.models import MutualFund
import time
import requests
import csv
from io import StringIO
CACHE_DURATION = 60 * 60 * 6  # 5 hours in seconds
import requests
from io import StringIO
from Myapp.models import AllMutualFund
#from dotenv import load_dotenv
#load_dotenv() 

from django.http import HttpResponse
from .notifications import send_daily_notifications

"""
def run_daily(request):
    send_daily_notifications()
    return HttpResponse("Daily notifications sent successfully!.")
"""

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

#It's for all fund data using fund type
def get_all_funds_data_by_indian_api():
    # URL for fetching mutual funds data
    url = "https://stock.indianapi.in/mutual_funds"
    
    # Headers to pass the API key
    headers = {"X-Api-Key": API_KEY}

    # Send GET request with the headers and params
    response = requests.get(url, headers=headers)

    # Return the JSON response if the request is successful
    if response.status_code == 200:
        return response.json()
    else:
        return []

def get_single_fund_data_by_indian_api(fund_name):
    url = "https://stock.indianapi.in/mutual_funds_details"
    querystring = {"stock_name": fund_name}
    headers = {"X-Api-Key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)

        if response.status_code == 200:
            data = response.json()

            # Check if 'error' is in response
            if 'error' in data or 'basic_info' not in data:
                return None

            return data
        else:
            return None
    except Exception:
        return None

# To show specific fund details using fund name
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
    
    current_time = time.time()
    # Try getting from Django cache
    cached_data = cache.get('cached_fund_result')
    last_fetched_time = cache.get('last_fetched_time', 0)

    print(f"LAST_FETCHED_TIME: {last_fetched_time}")
    print(f"CACHE_DURATION: {CACHE_DURATION}")
    print(f"Time since last fetch: {current_time - last_fetched_time}")

    if cached_data is not None and (current_time - last_fetched_time) < CACHE_DURATION and len(cached_data) > 1:
        print("✅ Using cached fund data.")
        context.update({
            'categorized_funds': cached_data,
            'show_table': True
        })
        print(f"✅ Fetched cached funds data")

    else:
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
        # Save to Django cache
        cache.set('cached_fund_result', categorized_funds, timeout=CACHE_DURATION)
        cache.set('last_fetched_time', current_time, timeout=CACHE_DURATION)

        print(f"✅ Fetched and cached new data. Total Funds: {len(categorized_funds)}")
    messages.success(request, "Fund result fetched successfully")
    # Default return for GET requests or invalid POST
    return render(request, 'Fund_result.html', context)

def fund_details(request):
    if request.user.is_anonymous:
        messages.info(request, "Session expired! Please login again.")
        return redirect('login')
    
    # Try getting from Django cache
    """
    cached_data = cache.get('all_funds_data')
    last_fetched_time = cache.get('last_fetched_time', 0)
    print(f"Cached Data:{cached_data}")
    print(f"Last Fetched Data:{last_fetched_time}")
    """
    #context = {}
    all_funds = AllMutualFund.objects.all()
    context = {
        'all_funds': all_funds,
    }

    filtered_funds = None
    if request.method == "POST":
        fund_name = request.POST.get('fund_name').strip()
        if not fund_name:
            messages.error(request, "Fund name is missing.")
            return redirect('fund_details')

        fund_data = get_single_fund_data_by_indian_api(fund_name)
        if (fund_data and isinstance(fund_data, dict) and 
            'basic_info' in fund_data and isinstance(fund_data['basic_info'], dict) and 
            fund_data['basic_info'].get('fund_name')):  
            try:
                basic_info = fund_data.get('basic_info', {})
                name_of_fund = basic_info.get('fund_name')
                returns = fund_data.get('returns', {})
                expense_ratio = fund_data.get('expense_ratio', {})
                context.update({
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
                })
                try:
                    new_fund = AllMutualFund(fund_name=name_of_fund)
                    new_fund.save()
                except Exception as e:
                    pass
                    #messages.success(request, "Mutual Fund Name already present.")

                messages.success(request, "Mutual Fund data fetched successfully.")
                return render(request, 'Fund_details.html', context)
            
            except ValueError as e:
                print(f"Error:{e}")
                pass

        else:
            filtered_funds = get_matching_funds(fund_name, 0.20)
            print(fund_name)
            if filtered_funds is not None and len(filtered_funds) > 0:
                #print(filtered_funds)
                # ✅ Convert keys to template-friendly format
                for fund in filtered_funds:
                    fund['scheme_name'] = fund.pop('Scheme Name', '')
                    fund['scheme_code'] = fund.get('Scheme Code', '')
                    fund['nav'] = fund.get('NAV', '')
                    fund['date'] = fund.get('Date', '')
                    fund['plan_type'] = fund.get('Plan Type', '')
                    fund['category'] = fund.get('Category', '')
                    fund['duration'] = fund.get('Duration', '')
                    fund['match_score'] = fund.get('Match Score', '')*100
                    try:
                        new_fund = AllMutualFund(fund_name=fund["scheme_name"])
                        new_fund.save()
                    except Exception as e:
                        pass
                messages.success(request, f"Recommended {len(filtered_funds)} Fund data successfully.")
                context.update({ 'filtered_funds': filtered_funds })
            else:
                messages.info(request, "No matching fund data available at the moment. Please try a different name or check back later.")

            #messages.info(request, "No data is available for the selected fund at the moment.")
    # Always return at least empty context
    return render(request, 'Fund_details.html', context)

def get_fund_data_from_amfi_using_web_scraping():
    current_time = time.time()
    #cache.delete('all_funds_data')
    # Try getting from Django cache
    cached_data = cache.get('all_funds_data')
    last_fetched_time = cache.get('last_fetched_time', 0)

    print(f"LAST_FETCHED_TIME: {last_fetched_time}")
    print(f"CACHE_DURATION: {CACHE_DURATION}")
    print(f"Time since last fetch: {current_time - last_fetched_time}")

    if cached_data is not None and (current_time - last_fetched_time) < CACHE_DURATION and len(cached_data) > 1:
        print("✅ Using cached fund data.")
        return cached_data

    # Fetch from AMFI
    url = "https://www.amfiindia.com/spages/NAVAll.txt"
    response = requests.get(url)

    if response.status_code != 200:
        print("❌ Failed to fetch data from AMFI.")
        return []

    data = response.text.strip().splitlines()
    start_idx = next(i for i, line in enumerate(data) if line.startswith("Scheme Code"))
    csv_data = "\n".join(data[start_idx:])
    f = StringIO(csv_data)
    reader = csv.DictReader(f, delimiter=';')

    funds = []
    for row in reader:
        if row.get('Scheme Name'):
            funds.append({
                'Scheme Name': row['Scheme Name'].strip(),
                'Scheme Code': row['Scheme Code'].strip(),
                'ISIN': row['ISIN Div Payout/ ISIN Growth'].strip(),
                'NAV': row['Net Asset Value'].strip(),
                'Date': row['Date'].strip(),
                'Plan Type': infer_plan_type(row['Scheme Name'].strip()),
                'Duration': infer_duration(row['Scheme Name'].strip()),
                'Category': infer_category(row['Scheme Name'].strip()),
            })

    # Save to Django cache
    cache.set('all_funds_data', funds, timeout=CACHE_DURATION)
    cache.set('last_fetched_time', current_time, timeout=CACHE_DURATION)

    print(f"✅ Fetched and cached new data. Total Funds: {len(funds)}")
    return funds

def infer_plan_type(name):
    name = name.lower()
    if 'direct' in name:
        return 'Direct'
    if 'regular' in name:
        return 'Regular'
    return 'Regular'  # Default to Regular if nothing is matched

def infer_duration(name):
    name = name.lower()
    if 'short' in name:
        return 'Short Term'
    if 'long' in name:
        return 'Long Term'
    if 'ultra' in name or 'overnight' in name:
        return 'Very Short Term'
    return 'Medium Term'

def infer_category(name):
    name = name.lower()
    if 'equity' in name:
        return 'Equity'
    if 'debt' in name or 'bond' in name:
        return 'Debt'
    if 'hybrid' in name:
        return 'Hybrid'
    if 'index' in name:
        return 'Index Fund'
    return 'Other'

def get_matching_funds(search_term, threshold=0.20):
    """Find funds with similar names using cosine similarity"""
    funds = get_fund_data_from_amfi_using_web_scraping()
    if not funds:
        print("Error: Funds data not fetched from amfiindia.")
        return []

    # Prepare data for similarity comparison
    vectorizer = TfidfVectorizer()
    fund_names = [
        f['Scheme Name'].lower()
        for f in funds
        if isinstance(f, dict) and 'Scheme Name' in f
    ]

    tfidf_matrix = vectorizer.fit_transform([search_term.lower()] + fund_names)
    
    # Calculate similarities
    similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]
    
    # Return matches above threshold, sorted by Match Score descending
    matched_funds = [
        {**fund, 'Match Score': float(score)}
        for fund, score in zip(funds, similarities)
        if score >= threshold
    ]

    matched_funds.sort(key=lambda x: x['Match Score'], reverse=True)
    
    return matched_funds[:20]

import numpy as np
from datetime import datetime
import requests

from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer

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
        #print(form_data.get('tenure'))
        if not any(form_data.values()):
            messages.error(request, "To get recommendations, choose at least one option from the dropdown menus.")
            return redirect('dashboard')
        
        context['form_data'] = form_data
        
        print(form_data)

        try:
            # Get fund data with special case flag
            processed_data = process_recommendations(form_data) 
            
            if processed_data:
                print(f"Successfully fetched {len(processed_data)} funds")
                messages.success(request, f"Recommended {len(processed_data)} funds successfully.")
                context["recommended_funds"] = processed_data
            else:
                messages.error(request, "Sorry, no recommendations match your current choices. Consider changing some filters.")

        except Exception as e:
            print(f"Recommendation processing error: {e}")
            messages.error(request, "System error during processing")

    return render(request, 'Index.html', context)
   
def get_funds_data_from_api(form_data):
    #print(form_data)
    fund_type = form_data.get('fund_type', None)

    tenure = form_data.get('tenure', '1_year_return').strip()
    
    # Add this validation (NEW CODE)
    valid_tenures = ['1_month_return', '3_month_return', '6_month_return', 
                    '1_year_return', '3_year_return', '5_year_return']
    if tenure not in valid_tenures:
        tenure = '1_year_return' # Force fallback to 1-year

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
                
                #print(f"Processing sub-category: {sub_category}")
                for fund_item in fund_list:
                    try:
                        if not isinstance(fund_item, dict):
                            #print(f"Skipping invalid fund data structure")
                            continue
                                # Get return value (NEW FALLBACK LOGIC)
                        return_value = fund_item.get(tenure, fund_item.get('1_year_return'))
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
                            'return_type': estimate_return_type_using_tenure(tenure, return_value),
                            'risk': estimate_risk_from_return_profile(fund_item),  # Optional: ensure risk is included
                        })
    
                    except Exception as e:
                        print(f"Error processing fund: {str(e)}")
                        continue

        print(f"Successfully processed {len(processed_data)} funds in category: {fund_type or 'All'}")
        return processed_data
        
    except Exception as e:
        print(f"Critical error: {str(e)}")
        return None

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from sklearn.preprocessing import StandardScaler
# Newer Function
def process_recommendations(form_data):
    all_funds = get_funds_data_from_api(form_data)
    if not all_funds:
        print("Error: No fund data available.")
        return []

    # Safely extract form data
    fund_type = form_data.get('fund_type', '').strip().lower()
    fund_subtype = form_data.get('fund_subtype', '').strip().lower()
    tenure = form_data.get('tenure', '1_year_return').strip()
    return_type = form_data.get('return_type', '').strip().lower()
    
    # Validate tenure
    if tenure not in all_funds[0]:
        tenure = '1_year_return'

    # Initialize fund buckets
    exact_match_funds = []
    type_only_match_funds = []
    subtype_only_match_funds = []
    other_funds = []

    for fund in all_funds:
        # Skip if no return data
        fund_return = float_or_none(fund.get(tenure))
        if fund_return is None:
            continue

        # Skip if doesn't match return type filter
        classified_return = estimate_return_type_using_tenure(tenure, fund_return).lower()
        if return_type and classified_return != return_type:
            continue

        fund_data = {
            **fund,
            'return_value': fund_return,
            'return_class': classified_return
        }

        # Check matches
        current_type = fund.get('category', '').lower()
        current_subtype = fund.get('sub_category', '').lower()
        
        type_match = not fund_type or current_type == fund_type
        subtype_match = not fund_subtype or current_subtype == fund_subtype

        if type_match and subtype_match:
            exact_match_funds.append(fund_data)
        elif type_match and fund_type:  # Only type matches (when type is specified)
            type_only_match_funds.append(fund_data)
        elif subtype_match and fund_subtype:  # Only subtype matches (when subtype is specified)
            subtype_only_match_funds.append(fund_data)
        else:
            other_funds.append(fund_data)

    # Determine which funds to use based on user selection
    if fund_type and fund_subtype:
        # When both are selected, try exact matches first, then mix of partial matches
        if exact_match_funds:
            filtered_funds = exact_match_funds
        else:
            # Combine type matches and subtype matches when no exact matches exist
            filtered_funds = type_only_match_funds + subtype_only_match_funds
            if not filtered_funds:
                filtered_funds = other_funds
    elif fund_type:
        # Only type selected - use only type matches
        filtered_funds = exact_match_funds + type_only_match_funds
    elif fund_subtype:
        # Only subtype selected - use only subtype matches
        filtered_funds = exact_match_funds + subtype_only_match_funds
    else:
        # Neither selected - use all funds
        filtered_funds = exact_match_funds + type_only_match_funds + subtype_only_match_funds + other_funds

    if not filtered_funds:
        print("No funds matched filters.")
        return []

    # Feature engineering
    texts = [
        ' '.join([
            fund.get('fund_name', '').lower(),
            fund.get('category', '').lower(),
            fund.get('sub_category', '').lower(),
            fund.get('return_class', '').lower()
        ])
        for fund in filtered_funds
    ]
    return_values = [[fund['return_value']] for fund in filtered_funds]

    # Vectorization
    tfidf = TfidfVectorizer()
    tfidf_matrix = tfidf.fit_transform(texts)

    scaler = StandardScaler()
    numeric_matrix = scaler.fit_transform(return_values)

    combined_matrix = np.hstack([tfidf_matrix.toarray(), numeric_matrix])

    # Build query from active filters
    user_text = ' '.join(filter(None, [
        fund_type,
        fund_subtype,
        return_type
    ])) or 'mutual fund'

    user_vector_text = tfidf.transform([user_text])
    user_vector_numeric = scaler.transform([[np.median(return_values)]])
    user_vector = np.hstack([user_vector_text.toarray(), user_vector_numeric])

    # Ranking
    similarities = cosine_similarity(user_vector, combined_matrix)[0]
    matched_funds = [
        {**filtered_funds[idx], 'similarity': round(score, 4)}
        for idx, score in enumerate(similarities)
        if score > 0
    ]
    #matched_funds.sort(key=lambda x: x['similarity'], reverse=True)

    return matched_funds[:10]

# New Function
"""def process_recommendations(form_data):
    all_funds = get_funds_data_from_api(form_data)
    if not all_funds:
        print("Error: No fund data available.")
        return []

    # Safely extract form data
    fund_type = form_data.get('fund_type', '').strip().lower()
    fund_subtype = form_data.get('fund_subtype', '').strip().lower()
    tenure = form_data.get('tenure', '1_year_return').strip()
    return_type = form_data.get('return_type', '').strip().lower()
    
    # Validate tenure
    if tenure not in all_funds[0]:
        tenure = '1_year_return'

    # Initialize fund buckets
    exact_match_funds = []
    type_match_funds = []
    subtype_match_funds = []
    other_funds = []

    for fund in all_funds:
        # Skip if no return data
        fund_return = float_or_none(fund.get(tenure))
        if fund_return is None:
            continue

        # Skip if doesn't match return type filter
        classified_return = estimate_return_type_using_tenure(tenure, fund_return).lower()
        if return_type and classified_return != return_type:
            continue

        fund_data = {
            **fund,
            'return_value': fund_return,
            'return_class': classified_return
        }

        # Check matches
        type_match = not fund_type or fund.get('category', '').lower() == fund_type
        subtype_match = not fund_subtype or fund.get('sub_category', '').lower() == fund_subtype

        if type_match and subtype_match:
            exact_match_funds.append(fund_data)
        elif type_match:
            type_match_funds.append(fund_data)
        elif subtype_match:
            subtype_match_funds.append(fund_data)
        else:
            other_funds.append(fund_data)

    # Determine which funds to use based on user selection
    if fund_type and fund_subtype:
        # When both are selected, try exact matches first, then mix of partial matches
        if exact_match_funds:
            filtered_funds = exact_match_funds
        else:
            # Combine type matches and subtype matches when no exact matches exist
            filtered_funds = type_match_funds + subtype_match_funds
            if not filtered_funds:
                filtered_funds = other_funds
    elif fund_type:
        # Only type selected - use type matches
        filtered_funds = type_match_funds
    elif fund_subtype:
        # Only subtype selected - use subtype matches
        filtered_funds = subtype_match_funds
    else:
        # Neither selected - use all funds
        filtered_funds = exact_match_funds + type_match_funds + subtype_match_funds + other_funds

    if not filtered_funds:
        print("No funds matched filters.")
        return []

    # Feature engineering
    texts = [
        ' '.join([
            fund.get('fund_name', '').lower(),
            fund.get('category', '').lower(),
            fund.get('sub_category', '').lower(),
            fund.get('return_class', '').lower()
        ])
        for fund in filtered_funds
    ]
    return_values = [[fund['return_value']] for fund in filtered_funds]

    # Vectorization
    tfidf = TfidfVectorizer()
    tfidf_matrix = tfidf.fit_transform(texts)

    scaler = StandardScaler()
    numeric_matrix = scaler.fit_transform(return_values)

    combined_matrix = np.hstack([tfidf_matrix.toarray(), numeric_matrix])

    # Build query from active filters
    user_text = ' '.join(filter(None, [
        fund_type,
        fund_subtype,
        return_type
    ])) or 'mutual fund'

    user_vector_text = tfidf.transform([user_text])
    user_vector_numeric = scaler.transform([[np.median(return_values)]])
    user_vector = np.hstack([user_vector_text.toarray(), user_vector_numeric])

    # Ranking
    similarities = cosine_similarity(user_vector, combined_matrix)[0]
    matched_funds = [
        {**filtered_funds[idx], 'similarity': round(score, 4)}
        for idx, score in enumerate(similarities)
        if score > 0
    ]
    matched_funds.sort(key=lambda x: x['similarity'], reverse=True)

    return matched_funds[:10]"""

#Old function
"""def process_recommendations(form_data):
    all_funds = get_funds_data_from_api(form_data)
    if not all_funds:
        print("Error: No fund data available.")
        return []

    # Safely extract form data
    fund_type = form_data.get('fund_type', '').strip().lower()
    fund_subtype = form_data.get('fund_subtype', '').strip().lower()
    tenure = form_data.get('tenure', '1_year_return').strip()
    return_type = form_data.get('return_type', '').strip().lower()
    
    # Validate tenure field exists in fund data
    if tenure not in all_funds[0] or tenure is None:
        tenure = '1_year_return'

    # Debug: Check available tenures (NEW CODE)
    #print("First fund's return fields:", [k for k in all_funds[0].keys() if '_return' in k])
    
    # Filter funds
    filtered_funds = []
    for fund in all_funds:
        fund_return = float_or_none(fund.get(tenure))
        if fund_return is None:
            continue

        classified_return = estimate_return_type_using_tenure(tenure, fund_return).lower()
        if return_type and classified_return != return_type:
            continue

        filtered_funds.append({
            **fund,
            'return_value': fund_return,
            'return_class': classified_return
        })

    if not filtered_funds:
        print("No funds matched filters.")
        return []

    # Feature engineering
    texts = [
        ' '.join([
            fund.get('fund_name', '').lower(),
            fund.get('category', '').lower(),
            fund.get('sub_category', '').lower(),
            fund.get('return_class', '').lower()
        ])
        for fund in filtered_funds
    ]
    return_values = [[fund['return_value']] for fund in filtered_funds]

    # Vectorization
    tfidf = TfidfVectorizer()
    tfidf_matrix = tfidf.fit_transform(texts)

    scaler = StandardScaler()  # Better for negative returns
    numeric_matrix = scaler.fit_transform(return_values)

    combined_matrix = np.hstack([tfidf_matrix.toarray(), numeric_matrix])

    # User query
    user_text = ' '.join(filter(None, [fund_type, fund_subtype, return_type]))
    if not user_text.strip():
        user_text = 'mutual fund'

    user_vector_text = tfidf.transform([user_text])
    user_vector_numeric = scaler.transform([[np.median(return_values)]])
    user_vector = np.hstack([user_vector_text.toarray(), user_vector_numeric])

    # Ranking
    similarities = cosine_similarity(user_vector, combined_matrix)[0]
    matched_funds = [
        {**filtered_funds[idx], 'similarity': round(score, 4)}
        for idx, score in enumerate(similarities)
        if score > 0  # Adjust threshold based on testing
    ]
    matched_funds.sort(key=lambda x: x['similarity'], reverse=True)

    return matched_funds[:10]"""

def estimate_return_type_using_tenure(tenure, return_rate):
    """Classifies returns into high/medium/low/negative based on tenure-specific thresholds."""
    try:
        # Validate input
        if return_rate is None:
            return "na"
        
        return_rate = float(return_rate)
        
        # Define thresholds (adjust as needed)
        thresholds = {
            "3_month_return": {"high": 8, "medium": 4},
            "6_month_return": {"high": 10, "medium": 6},
            "1_year_return": {"high": 12, "medium": 8},
            "3_year_return": {"high": 15, "medium": 8},
            "5_year_return": {"high": 25, "medium": 12}
        }
        
        # Get thresholds or use conservative defaults
        tenure_thresholds = thresholds.get(tenure, {"high": 10, "medium": 5})
        
        if return_rate < 0:
            return "negative"
        elif return_rate >= tenure_thresholds["high"]:
            return "high"
        elif return_rate >= tenure_thresholds["medium"]:
            return "medium"
        else:
            return "low"
            
    except (TypeError, ValueError):
        return "na"
    except Exception as e:
        print(f"Classification error: {e}")
        return "na"

def estimate_risk_from_return_profile(fund_data):
    try:
        # Extract valid returns
        returns = []
        for key in ['1_month_return', '3_month_return', '6_month_return', '1_year_return', '3_year_return', '5_year_return']:
            value = fund_data.get(key)
            if value is not None:
                try:
                    returns.append(float(value))
                except ValueError:
                    continue

        if len(returns) < 2:
            return "NA"

        # Calculate average
        avg_return = sum(returns) / len(returns)

        # Calculate standard deviation (manual)
        variance = sum((x - avg_return) ** 2 for x in returns) / (len(returns) - 1)
        std_dev = variance ** 0.5

        # Risk classification based on volatility
        if std_dev < 2:
            return "Low"
        elif std_dev < 4:
            return "Medium"
        else:
            return "High"

    except Exception as e:
        print(f"Risk estimation error: {e}")
        return "NA"

def float_or_none(value):
    try:
        return round(float(value), 2)
    except:
        return None

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
            latest_nav = request.POST['nav']
            star_rating = request.POST['rating']
            print(f"Fund Name: {fund_name}, Investment Type: {investment_type}, Subcategory: {subcategory}, NAV:{latest_nav}, Rating:{star_rating}")
            #yearly_return = request.POST['yearly_return']
            if not fund_name or not investment_type or not subcategory or not latest_nav or not star_rating:
                messages.error(request, "All fields are required.")

            else:            
                existing_fund = MutualFund.objects.filter(username=username, fund_name=fund_name)
                if existing_fund:
                    messages.error(request, "Looks like this fund is already added, no need to do it twice!")

                else:
                    fund_data = MutualFund.objects.create(
                            username=username,
                            fund_name=fund_name,
                            investment_type=investment_type,
                            subcategory=subcategory,
                            nav=latest_nav,
                            rating=star_rating
                            )
                    
                    fund_data.save()
                    messages.success(request, "Your fund details have been saved with care and precision.")

    try:
        if username:
            fund_details = MutualFund.objects.filter(username=username)

    except Exception as e:
        messages.error(request, "Unable to fetch your fund right now!")
    return render(request, 'Your_funds.html', {'fund_details':fund_details})

# Page for showing user info
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import get_object_or_404

@login_required
def your_info(request, username=None):
    # If no username provided, show current user's profile
    target_username = username or request.user.username
    
    try:
        user_info = get_object_or_404(User, username=target_username)
        
        # Verify permission if viewing another user's profile
        if target_username != request.user.username and not request.user.is_staff:
            messages.error(request, "You don't have permission to view this profile")
            return redirect('home')
            
        try:
            profilepic = ProfilePic.objects.get(username=request.user).filename.url
        except ProfilePic.DoesNotExist:
            profilepic = None  # No profile picture found
        
        context = {
            'user_info': user_info,
            'profilepic': profilepic,
            'is_own_profile': (target_username == request.user.username)
        }
        
        messages.success(request, "Profile data loaded successfully")
        return render(request, 'Your_info.html', context)

    except Exception as e:
        messages.error(request, f"Error loading profile: {str(e)}")
        return redirect('dashboard')
    
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
