from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.views.decorators.cache import never_cache
from django.contrib.auth.models import User
from django.contrib import messages
from Myapp.models import Contact
from django.utils.timezone import now
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
import random

# Required Library or Module for Making Recommendation
from .models import MutualFund, Rating
import numpy as np
import yfinance as yf
from sklearn.metrics.pairwise import cosine_similarity
from scipy.sparse import coo_matrix
from implicit.als import AlternatingLeastSquares
import yfinance as yf
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

def get_real_time_data(ticker):
    """Fetch real-time data (Closing prices) from Yahoo Finance."""
    try:
        fund = yf.Ticker(ticker)
        historical_data = fund.history(period="5y")  # Fetch 5 years of data (adjust period as necessary)
        
        if historical_data.empty:
            return None
        return historical_data['Close']  # You can extend this to use other metrics like volume, etc.
    except Exception as e:
        print(f"Error fetching data for {ticker}: {e}")
        return None

def content_based_recommendation(company_type, risk_level, top_n=5):
    """Recommend funds based on company type and risk level using Yahoo Finance data."""
    # Fetch all the funds based on the category (company_type) and risk level
    funds = MutualFund.objects.filter(category=company_type, risk=risk_level)
    
    print(f"Funds found: {funds}")  # Debugging to check the result of the filter

    # If no funds are found, return empty list or default recommendation
    if not funds:
        return ['No funds found']

    # Prepare fund data based on Yahoo Finance
    fund_data = []
    for fund in funds:
        real_time_data = get_real_time_data(fund.ticker)  # Fetch real-time data for each fund
        if real_time_data is not None:
            avg_return = real_time_data.pct_change().mean() * 100  # Calculate average return rate
        else:
            avg_return = 0  # If real-time data is not available, assume zero return rate
        
        fund_data.append((fund.id, fund.category, fund.risk, avg_return))

    # If no valid fund data was found, return empty list
    if not fund_data:
        return ['Fund data not available!']

    # Generate a feature matrix based on category, risk, and average return rate
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
    recommended_funds = [funds[i[0]] for i in scores]
    print(f"Recommended Funds: {recommended_funds}")
    return recommended_funds

def collaborative_recommendation(user_id, top_n=5):
    ratings = Rating.objects.all()
    if len(ratings) < 5:
        return []
    
    user_ids = {r.user_id for r in ratings}
    fund_ids = {r.fund.id for r in ratings}

    user_map = {uid: i for i, uid in enumerate(user_ids)}
    fund_map = {fid: i for i, fid in enumerate(fund_ids)}
    
    rows = np.array([user_map[r.user_id] for r in ratings])
    cols = np.array([fund_map[r.fund.id] for r in ratings])
    data = np.array([r.rating for r in ratings])
    
    rating_matrix = coo_matrix((data, (rows, cols)), shape=(len(user_ids), len(fund_ids)))

    model = AlternatingLeastSquares(factors=50, iterations=10, regularization=0.1)
    model.fit(rating_matrix.T)

    user_index = user_map.get(user_id)
    if user_index is None:
        return []

    recommendations = model.recommend(user_index, rating_matrix, N=top_n)
    return [MutualFund.objects.get(id=list(fund_map.keys())[i]) for i, _ in recommendations]

def hybrid_recommendation(user_id, company_type, risk_level, top_n=5):
    user_ratings = Rating.objects.filter(user_id=user_id).count()
    
    # If the user has rated fewer than 3 funds, use content-based recommendation
    if user_ratings < 3:
        return content_based_recommendation(company_type, risk_level, top_n)
    else:
        collaborative_results = collaborative_recommendation(user_id, top_n)
        if not collaborative_results:
            # Fallback to content-based if no collaborative results
            return content_based_recommendation(company_type, risk_level, top_n)
        return collaborative_results

def recommend_funds(request):
    recommended_funds = None
    if request.method == 'POST':
        # Get user inputs from the form
        company_type = request.POST.get('company_type')
        risk_level = request.POST.get('risk')
        investment_type = request.POST.get('investment_type')
        duration = request.POST.get('duration')
        profit_type = request.POST.get('profit_type')
        profit_percentage = request.POST.get('profit_percentage')
        custom_profit = request.POST.get('custom_profit')

        # Ensure essential fields are filled
        if not company_type or not risk_level or not investment_type or not duration or not profit_type or not profit_percentage:
            messages.error(request, "Please fill all required fields.")
            return redirect('recommend_funds')  # Redirect back to the form

        # Handle custom profit percentage
        if profit_percentage == "other" and custom_profit:
            try:
                profit_percentage = float(custom_profit)
            except ValueError:
                messages.error(request, "Invalid custom profit percentage.")
                return redirect('recommend_funds')

        # Assume user_id can be retrieved from the session or user model
        user_id = request.user.id  # Example, adjust as needed

        # Get recommended funds
        recommended_funds = hybrid_recommendation(user_id, company_type, risk_level)

        # Store recommended funds in the session
        recommended_fund_ids = [fund.id for fund in recommended_funds]
        request.session['recommended_funds'] = recommended_fund_ids

        messages.success(request, "Recommendations generated successfully!")
        return redirect('dashboard')  # Redirect to dashboard to show the recommendations

@never_cache
def userdashboard(request):
    if request.user.is_anonymous:
        messages.warning(request, "Session expired! Please login again.")
        return redirect('home')  # Redirect anonymous users to home
    
    session_expiry = request.session.get_expiry_date()  # Get session expiry time
    current_time = now()  # Get current server time
    remaining_time = (session_expiry - current_time).total_seconds()  # Calculate remaining time
    
    # Format full name properly
    full_name = request.session.get('full_name', '')  # Retrieve from session, with a fallback to empty string
    username = request.session.get('username', '')  # Retrieve from session
    
    # If the user doesn't have a first or last name, fallback to username
    if not full_name:
        full_name = username

    # Retrieve recommended funds from session
    recommended_fund_ids = request.session.get('recommended_funds', [])
    recommended_funds = MutualFund.objects.filter(name=recommended_fund_ids) if recommended_fund_ids else []

    context = {
        "remaining_time": remaining_time,
        "full_name": full_name,
        "recommended_funds": recommended_funds,
    }

    return render(request, 'Index.html', context)  # Render the dashboard page
