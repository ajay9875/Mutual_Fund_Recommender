from .models import MutualFund, Rating
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from scipy.sparse import coo_matrix
from implicit.als import AlternatingLeastSquares

def content_based_recommendation(fund_id, company_type, risk_level, top_n=5):
    funds = MutualFund.objects.filter(category=company_type, risk=risk_level)
    
    if not funds.exists():
        return []  # Return empty if no funds match

    try:
        selected_fund = MutualFund.objects.get(id=fund_id)
    except MutualFund.DoesNotExist:
        return []  # Return empty if fund_id is invalid

    fund_data = [(f.id, f.return_rate) for f in funds]

    feature_matrix = np.array([[f[1]] for f in fund_data])  # Use return_rate as feature
    similarities = cosine_similarity(feature_matrix)

    fund_index = [f[0] for f in fund_data].index(fund_id)  # Find index of selected fund

    scores = list(enumerate(similarities[fund_index]))
    scores = sorted(scores, key=lambda x: x[1], reverse=True)[1:top_n+1]

    recommended_fund_ids = [fund_data[i[0]][0] for i in scores]
    return MutualFund.objects.filter(id__in=recommended_fund_ids)

def collaborative_recommendation(user_id, top_n=5):
    ratings = Rating.objects.all()

    if len(ratings) < 5:
        return []  # Not enough data for collaborative filtering

    users = {r.user.id for r in ratings}
    funds = {r.fund.id for r in ratings}

    user_map = {uid: i for i, uid in enumerate(users)}
    fund_map = {fid: i for i, fid in enumerate(funds)}

    rows = np.array([user_map[r.user.id] for r in ratings])
    cols = np.array([fund_map[r.fund.id] for r in ratings])
    data = np.array([r.rating for r in ratings])

    rating_matrix = coo_matrix((data, (rows, cols)), shape=(len(users), len(funds)))

    model = AlternatingLeastSquares(factors=50, iterations=10, regularization=0.1)
    model.fit(rating_matrix.T)

    user_index = user_map.get(user_id)
    if user_index is None:
        return []

    recommendations = model.recommend(user_index, rating_matrix, N=top_n)
    recommended_fund_ids = [list(fund_map.keys())[i] for i, _ in recommendations]

    return MutualFund.objects.filter(id__in=recommended_fund_ids)

def hybrid_recommendation(user_id, fund_id, company_type, risk_level, top_n=5):
    user_ratings = Rating.objects.filter(user_id=user_id).count()

    if user_ratings < 3:
        return content_based_recommendation(fund_id, company_type, risk_level, top_n)
    
    collaborative_results = collaborative_recommendation(user_id, top_n)
    
    if not collaborative_results:
        return content_based_recommendation(fund_id, company_type, risk_level, top_n)
    
    return collaborative_results
