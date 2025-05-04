import yfinance as yf

def get_real_time_data(ticker_symbol):
    """
    Fetch real-time mutual fund historical NAV data using Yahoo Finance.
    :param ticker_symbol: The mutual fund's stock ticker symbol
    :return: DataFrame containing historical NAV data or error message
    """
    try:
        fund = yf.Ticker(ticker_symbol)
        historical_data = fund.history(period="5y")  # Fetch last 5 years' data

        if historical_data.empty:
            return "No data available for this mutual fund."

        return historical_data

    except Exception as e:
        return str(e)
