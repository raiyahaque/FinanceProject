import os

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
    stock_total = 0
    # Get all of the user's stocks
    stocks = db.execute("SELECT * FROM stocks WHERE user_id = :user_id", user_id=session["user_id"])
    # If they have stocks
    if stocks:
        for stock in stocks:
            symbol = stock['symbol']
            results = lookup(symbol)
            # Get latest stock price
            stock_price = results["price"]
            # Update stock price in stocks table to the latest price
            db.execute("UPDATE stocks SET price = :price, total = :total WHERE symbol = :symbol AND user_id = :user_id", price=stock_price, total=stock_price*stock['shares'], symbol=symbol, user_id=session["user_id"])
            # Sum up total amount of money spent on stocks
            stock_total += stock['total']
        row = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        # Get how much money user has left
        remaining_cash = round(row[0]['cash'],2)
        total_cash = round(remaining_cash + stock_total, 2)
        return render_template("index.html", stocks=stocks, remaining_cash=remaining_cash, total_cash=total_cash)
    else:
        return render_template("index.html", stocks=stocks, remaining_cash=10000, total_cash=10000)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        if not request.form.get("symbol"):
            return apology("Please enter a symbol.", 403)
        symbol = request.form.get("symbol")
        # Lookup the symbol
        results = lookup(symbol)
        if results == None:
            return apology("Symbol does not exist", 403)
        if not request.form.get("shares"):
            return apology("Please enter a number of shares.", 403)
        shares = int(request.form.get("shares"))
        # If shares is not a positive integer
        if isinstance(shares, int) == False or shares <= 0:
            return apology("Shares needs to be a positive integer", 403)
        current_price = round(results["price"], 2)
        # Get the cash amount of the user
        rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        current_cash = rows[0]['cash']
        # Get total price of stocks
        total = round(current_price*shares,2)
        # If user has enough cash for the stocks
        if total < current_cash:
            # Check if user already owns stocks from the company
            rows = db.execute("SELECT * FROM stocks WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=session["user_id"])
            # If user already owns stocks from the company
            if len(rows) > 0:
                # Update number of shares and total
                new_shares = int(rows[0]['shares']) + int(shares)
                new_total = round(float(rows[0]['total']) + float(total), 2)
                db.execute("UPDATE stocks SET shares = :shares, total = :total WHERE symbol = :symbol AND user_id = :user_id", shares=new_shares, total=new_total, symbol=symbol, user_id=session["user_id"])
            # User does not already own stocks from the company
            else:
                db.execute("INSERT INTO stocks (symbol, name, shares, price, total, user_id) VALUES(:symbol, :name, :shares, :price, :total, :user_id)", symbol=symbol, name=results["name"], shares=shares, price=results["price"], total=total, user_id=session["user_id"])
            # Update cash in users table
            remaining_cash = current_cash - total
            db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=remaining_cash, id=session["user_id"])
            # Record the transaction in the history table
            db.execute("INSERT INTO history (symbol, shares, price, user_id) VALUES(:symbol, :shares, :price, :user_id)", symbol=symbol, shares=shares, price=results["price"], user_id=session["user_id"])
            message = 'Bought!'
            flash(message)
            return redirect("/")
        # User does not have enough cash to purchase the stocks
        else:
            return apology("Not enough cash to purchase shares.", 403)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get all transactions made by the user
    transactions = db.execute("SELECT * FROM history WHERE user_id = :user_id ORDER BY transaction_time DESC", user_id=session["user_id"])
    return render_template("history.html", stocks=transactions)

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
    if request.method == 'POST':
        if not request.form.get("symbol"):
            return apology("No symbol entered. Please enter a symbol.", 403)
        symbol = request.form.get("symbol")
        # Lookup the symbol
        results = lookup(symbol)
        if results != None:
            return render_template("quoted.html", name=results["name"], symbol=results["symbol"], price=results["price"])
        else:
            return apology("Symbol does not exist", 403)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)
        if not request.form.get("confirm_password"):
            return apology("must confirm password", 403)

        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if password == confirm_password:
            if len(db.execute("SELECT * FROM users WHERE username = :username", username=username)) == 0:
                db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=username, hash=generate_password_hash(password))
                return render_template("login.html")
            else:
                error = "This username is already taken. Please enter a different username."
                flash(error)
                return redirect("/register")
        else:
            return apology("Password and confirmed password do not match.", 403)
    else:
        return render_template("registration.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        if not request.form.get("shares"):
            return apology("must provide shares", 403)
        symbol = request.form.get("symbol")
        results = lookup(symbol)
        shares = request.form.get("shares")
        if int(shares) <= 0:
            return apology("shares needs to be a positive integer", 403)
        # Get the stock that the user wants to sell
        stock = (db.execute("SELECT * FROM stocks WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=session["user_id"]))[0]
        # Calculate total price
        total_price = float(results['price'])*float(shares)
        # Make shares negative because they are being sold
        selling_shares = -1*int(shares)
        # User does not have the number of stocks he/she wants to sell
        if int(shares) > int(stock['shares']):
            return apology("You do not own enough shares of this stock", 403)
        # If user owns the exact number of stocks he/she wants to sell
        elif int(shares) == int(stock['shares']):
            db.execute("DELETE FROM stocks WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=session["user_id"])

        else:
            # Update number of shares in stocks table
            new_shares_amount = int(stock['shares']) - int(shares)
            db.execute('UPDATE stocks SET shares = :shares WHERE symbol = :symbol AND user_id = :user_id', shares=new_shares_amount, symbol=symbol, user_id=session["user_id"])
            # Get new total amount and update the stocks table
            new_total = float(new_shares_amount)*float(results['price'])
            db.execute('UPDATE stocks SET total = :total WHERE symbol = :symbol AND user_id = :user_id', total=new_total, symbol=symbol, user_id=session["user_id"])

        # Get the amount of cash the user had from the users table
        rows = db.execute("SELECT * FROM users WHERE id = :id", id=session["user_id"])
        old_cash_amount = rows[0]['cash']
        # Update cash amount by adding the total price of the stocks he/she sold
        new_cash_amount = old_cash_amount + total_price
        db.execute('UPDATE users SET cash = :cash WHERE id = :id', cash=new_cash_amount , id=session["user_id"])
        # Record the transaction in the history table
        db.execute("INSERT INTO history (symbol, shares, price, user_id) VALUES(:symbol, :shares, :price, :user_id)", symbol=symbol, shares=selling_shares, price=results["price"], user_id=session["user_id"])
        message = "Sold!"
        flash(message)
        return redirect("/")

    else:
        stocks = db.execute("SELECT * FROM stocks WHERE user_id = :id", id=session["user_id"])
        return render_template("sell.html", stocks=stocks)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == 'POST':
        if not request.form.get("new_password"):
            return apology("You did not fill in a new password.", 403)
        if not request.form.get("confirm_password"):
            return apology("Please confirm your password.", 403)
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")
        if new_password == confirm_password:
            # Update user's password in the users table
            db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=generate_password_hash(new_password), id=session["user_id"])
            return redirect("/")
        else:
            return apology("New password and confirmed password do not match.", 403)
    else:
        return render_template("change_password.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
