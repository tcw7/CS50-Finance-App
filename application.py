import os
import time

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():

    """Show portfolio of stocks"""

    # user has requested to see the index page
    if request.method == "GET":

        # calculate cash available
        cashDict = db.execute("SELECT cash FROM users WHERE (id = :id)", id=session["user_id"])
        cashAvail = round(cashDict[0]["cash"], 2)

        # calculate list of assets
        assets = db.execute("SELECT DISTINCT ticker FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])

        # calculate number of shares owned per ticker
        for item in assets:
            totalQty = 0
            qtyDict = db.execute("SELECT qty FROM transactions WHERE ticker = :ticker", ticker=item["ticker"])
            for row in qtyDict:
                totalQty += int(row["qty"])
            item["qty"] = totalQty

        # calculate current price, set company name
        for item in assets:
            tickerInfo = lookup(item["ticker"])
            item["name"] = tickerInfo["name"]
            item["price"] = round(tickerInfo["price"], 2)

        # calculate current value
        for item in assets:
            currentValue = round((item["price"] * item["qty"]), 2)
            item["current_value"] = currentValue

        # calculate total liquid value
        cash_total = 0
        for item in assets:
            cash_total = cash_total + round((item["price"] * item["qty"]), 2)
        cash_total = round((cash_total + cashAvail), 2)

        # show webpage
        return render_template("index.html", cash=cashAvail, assets=assets, cash_total=cash_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():

    """Buy shares of stock"""

    # user requests the BUY page
    if request.method == "GET":
        return render_template("buy.html")

    # user has submitted a purchase order
    if request.method == "POST":

        # check if the symbol exists in API
        tickerInfo = lookup(request.form.get("ticker"))
        if not tickerInfo:
            return apology("Your ticker symbol cannot be found.")

        # check to make sure "shares" is a valid integer
        if not request.form.get("shares"):
            return apology("The number of shares you requested to purchase is not valid. Please enter an integer greater than 0.")
        qtyShares = int(request.form.get("shares"))
        if qtyShares <= 0:
            return apology("The number of shares you requested to purchase is not valid. Please enter an integer greater than 0.")

        # check if user has enough funds
        pricePerShare = round(tickerInfo["price"], 2)
        totalPrice = round((pricePerShare * qtyShares), 2)
        fundsDict = db.execute("SELECT cash FROM users WHERE (id = :id)", id=session["user_id"])
        currentFunds = float(fundsDict[0]["cash"])
        if totalPrice > currentFunds:
            return apology("The total price exceeds your current funds.")

        # subtract funds from user
        updateFunds = currentFunds - totalPrice
        db.execute("UPDATE users SET cash = :funds", funds=updateFunds)

        # add transaction to transaction table
        db.execute("INSERT INTO transactions (user_id, ticker, price, qty) VALUES (:user_id, :ticker, :price, :qty)",
            user_id=session["user_id"], ticker=tickerInfo["symbol"], price=pricePerShare, qty=qtyShares)

        # return user to homepage
        flash(f'Your purchase of {qtyShares} share(s) of {tickerInfo["symbol"]} was successful.')
        return redirect("/")


@app.route("/history")
@login_required
def history():

    """Show history of transactions"""
    # user has requested the history.html page
    if request.method == "GET":

        # put SQL query into a variable
        history = db.execute("SELECT * FROM transactions WHERE user_id = :user_id",
            user_id=session["user_id"])

        # check to see if there are any transactions
        if not history:
            return apology("You have not made any transactions yet!")

        # assign variables to state of BUY and SELL
        bought = "bought"
        sold = "sold"

        return render_template("history.html", history=history, bought=bought, sold=sold)

    # return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    """Get stock quote."""
    # user is requesting the quotes page
    if request.method == "GET":
        return render_template("quote.html")

    # user is requesting a particular ticker symbol
    if request.method == "POST":

        # store ticker in a variable
        tickr = request.form.get("ticker")

        # lookup ticker symbol and store in a var
        tickerInfo = lookup(tickr)

        if not tickerInfo:
            return apology("Sorry, we can't find that ticker symbol")

        else:
            return render_template("quoted.html", tickerInfo=tickerInfo)


@app.route("/register", methods=["GET", "POST"])
def register():

    """Register user"""
    # user has submitted an intention to register
    if request.method == "POST":

        # check if username field is empty
        if not request.form.get("username"):
            return apology("Your username cannot be blank. Please enter a username.")

        # check if password field is not empty
        if not request.form.get("password"):
            return apology("Your password cannot be blank. Please enter a password")

        # check if confirmation of password matches
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("Your passwords do not match. Please try again.")

        # generate a hash of the user's password
        newHash = generate_password_hash(request.form.get("password"))

        # input new user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
            request.form.get("username"), newHash)

        # flash a successful message
        # redirect to login
        flash("You've been registered!")
        return render_template("login.html")

    # user is requesting registration page
    else:
        return render_template("register.html")

@app.route("/password", methods=["GET", "POST"])
def password():

    """Register user"""
    # user has submitted an intention to change passwords
    if request.method == "POST":

        # check if old_password_1 field is empty
        if not request.form.get("old_password_1"):
            return apology("Your password cannot be blank. Please enter your old password.")

        # check if old_password_2 matches old_password_1
        if request.form.get("old_password_1") != request.form.get("old_password_2"):
            return apology("Your passwords do not match. Please re-renter your old password correctly.")

        # check hash on the old password
        oldHash = db.execute("SELECT hash from users WHERE id = :id", id=session["user_id"])
        if not check_password_hash(oldHash[0]["hash"], request.form.get("old_password_2")):
            return apology("Your old password was entered incorrectly. Please try again.")

        # check if new_password field is empty
        if not request.form.get("new_password"):
            return apology("Your new password cannot be blank. Please enter a new password.")

        # generate a new hash of the user's password
        newHash = generate_password_hash(request.form.get("new_password"))

        # input new hash into database
        db.execute("UPDATE users SET hash = :newHash WHERE id = :id", newHash=newHash, id=session["user_id"])

        # flash a successful message
        # redirect to homepage
        flash("You have updated your password successfully!")
        return redirect("/")

    # user is requesting registration page
    else:
        return render_template("password.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    """Sell shares of stock"""

    # user has requested to access sell.html
    if request.method == "GET":

        # find all assets owned by user
        assets = db.execute("SELECT DISTINCT ticker FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])

        # render new sell.html
        return render_template("sell.html", assets=assets)

    # use has requested a sell order
    if request.method == "POST":

        # check if the symbol exists in API
        tickerInfo = lookup(request.form.get("ticker"))
        if not tickerInfo:
            return apology("Your ticker symbol cannot be found.")

        # check to make sure "shares" is a valid integer
        qtyShares = int(request.form.get("shares"))
        if qtyShares <= 0:
            return apology("The number of shares you requested to purchase is not valid. Please enter an integer greater than 0.")

        # search database for ownership of ticker
        assets = db.execute("SELECT * FROM transactions WHERE user_id = :user_id and ticker = :ticker", user_id=session["user_id"], ticker=tickerInfo["symbol"])

        # calculate number of shares owned of ticker, make sure they have enough
        totalQty = 0
        for item in assets:
            totalQty = totalQty + int(item["qty"])
        if totalQty < int(request.form.get("shares")):
            return apology(f'Sorry, you do not own enough shares of {request.form.get("ticker")} to sell {request.form.get("shares")} shares.')

        # check current user funds and net proceeds from sale of shares
        pricePerShare = round(tickerInfo["price"], 2)
        totalPrice = round((pricePerShare * qtyShares), 2)
        fundsDict = db.execute("SELECT cash FROM users WHERE (id = :id)", id=session["user_id"])
        currentFunds = float(fundsDict[0]["cash"])

        # add funds to user, add sale transaction
        db.execute("INSERT INTO transactions (user_id, ticker, price, qty) VALUES (:user_id, :ticker, :price, :qty)",
            user_id=session["user_id"], ticker=tickerInfo["symbol"], price=pricePerShare, qty=int(qtyShares * -1))
        updateFunds = currentFunds + totalPrice
        db.execute("UPDATE users SET cash = :funds", funds=updateFunds)

        # send user back to portfolio
        flash(f'You have successfully sold {request.form.get("shares")} share(s) of {request.form.get("ticker")}.')
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
