from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    # Fetch user's stock portfolio
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    # Initial variables for total values
    total_value = cash
    grand_total = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = stock["price"] * stock["total_shares"]
        total_value += stock["value"]
        grand_total += stock["value"]

    return render_template("index.html", stocks=stocks, cash=usd(cash), total_value=usd(total_value), grand_total=usd(grand_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Get user inputs from the form
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Validate inputs
        if not symbol:
            return apology("Must give Symbol")
        elif not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("Shares must be a positive integer")

        # Lookup stock information
        stock = lookup(symbol)
        if stock is None:
            return apology("Symbol does not exist")

        # Calculate transaction value
        transaction_value = int(shares) * stock["price"]

        # Get user information
        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        # Check if the user can afford the transaction
        if user_cash < transaction_value:
            return apology("Not enough money")

        # Update user's cash
        update_cash = user_cash - transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", update_cash, user_id)

        # Update transactions table
        date = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
            user_id, stock["symbol"], shares, stock["price"], date
        )

        flash(f"Bought {shares} of {symbol} for {usd(transaction_value)}, Updated cash: {usd(update_cash)}")
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions_db = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions_db)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """User can add cash"""
    if request.methods == "GET":
        return render_template("add.html")
    else:
        new_cash = int(request.method.get("new_cash"))

        if not new_cash:
            return apology("You Must Give Money")

        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        uptd_cash = user_cash + new_cash

        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_cash, user_id)

        return redirect("/")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("Must Give Symbol")

        stock = lookup(symbol.upper())

        if stock is None:
            return apology("Symbol Does Not Exist")

        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Must Give Username")

        if not password:
            return apology("Must Give Password")

        if not confirmation:
            return apology("Must Give Confirmation")

        if password != confirmation:
            return apology("Password Do Not Match")

        hash = generate_password_hash(password)

        try:
            new_user = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username already exists")
        session["user_id"] = new_user

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        symbols_user = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols_user])
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not shares.isdigit() or int(shares) <= 0:
            return apology("You cannot sell zero or negative shares.")

        if not symbol:
            return apology("Must Give Symbol")

        stock = lookup(symbol.upper())

        if stock is None:
            return apology("Symbol Does Not Exist")

        transaction_value = int(shares) * stock["price"]

        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        user_cash = user_cash_db[0]["cash"]

        user_shares = db.execute(
            "SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)
        user_shares_real = user_shares[0]["shares"]

        if int(shares) > user_shares_real:
            return apology("You Do Not Have This Amount Of Shares")

        uptd_cash = user_cash + transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_cash, user_id)

        date = datetime.datetime.now()

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
                   user_id, stock["symbol"], (-1) * int(shares), stock["price"], date)

        flash("Sold!")

        return redirect("/")
