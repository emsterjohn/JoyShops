import os
import sqlite3
from functools import wraps
from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("JOYSHOP_DB", os.path.join(APP_DIR, "joyshop.db"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-before-deployment")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER", "") == "true"
csrf = CSRFProtect(app)


def get_db():
    if "db" not in g:
        folder = os.path.dirname(DB_PATH)
        if folder:
            os.makedirs(folder, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        price REAL NOT NULL CHECK(price >= 0),
        stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
        emoji TEXT NOT NULL DEFAULT '🛍️',
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        total REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Processing',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
        product_name TEXT NOT NULL,
        unit_price REAL NOT NULL,
        quantity INTEGER NOT NULL CHECK(quantity > 0)
    );
    """)
    # Add checkout fields safely for existing databases created by earlier versions.
    order_columns = {row[1] for row in db.execute("PRAGMA table_info(orders)").fetchall()}
    for column, definition in {
        "phone": "TEXT NOT NULL DEFAULT ''",
        "address": "TEXT NOT NULL DEFAULT ''",
        "payment_method": "TEXT NOT NULL DEFAULT 'COD'",
        "payment_note": "TEXT NOT NULL DEFAULT ''",
        "customer_hidden": "INTEGER NOT NULL DEFAULT 0",
        "admin_hidden": "INTEGER NOT NULL DEFAULT 0",
    }.items():
        if column not in order_columns:
            db.execute(f"ALTER TABLE orders ADD COLUMN {column} {definition}")
    db.commit()

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@joyshop.com").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    admin = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
            ("JoyShop Administrator", admin_email, generate_password_hash(admin_password), "admin", now())
        )

    count = db.execute("SELECT COUNT(*) AS n FROM products").fetchone()["n"]
    if count == 0:
        samples = [
            ("Blush Everyday Tote", "Bags", "A roomy everyday bag with a soft, timeless look.", 599, 12, "👜"),
            ("Classic White Sneakers", "Shoes", "Clean and comfortable sneakers for everyday outfits.", 899, 9, "👟"),
            ("Soft Pink Cardigan", "Clothing", "A cozy layer for cool days and casual looks.", 749, 7, "🧥"),
            ("Pearl Charm Necklace", "Accessories", "A delicate finishing touch for your favorite outfit.", 299, 18, "📿"),
            ("Mini Shoulder Bag", "Bags", "A compact bag made for your daily essentials.", 499, 15, "👛"),
            ("Daily Comfort Flats", "Shoes", "Easy-to-style flats for all-day comfort.", 650, 8, "🥿"),
            ("Casual Weekend Tee", "Clothing", "A soft wardrobe basic for relaxed weekends.", 350, 20, "👚"),
            ("Cute Hair Clip Set", "Accessories", "Sweet little details to complete your look.", 159, 25, "🎀"),
        ]
        db.executemany(
            "INSERT INTO products (name,category,description,price,stock,emoji,created_at) VALUES (?,?,?,?,?,?,?)",
            [(*p, now()) for p in samples]
        )
    db.commit()


def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        g.user = get_db().execute(
            "SELECT id,name,email,role FROM users WHERE id = ?", (user_id,)
        ).fetchone()


@app.context_processor
def inject_globals():
    return {"current_user": getattr(g, "user", None), "year": datetime.now().year}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    if g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("shop"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Enter your name and email. Password must be at least 8 characters.", "danger")
        else:
            db = get_db()
            exists = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if exists:
                flash("An account with that email already exists.", "danger")
            else:
                cur = db.execute(
                    "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                    (name, email, generate_password_hash(password), "customer", now())
                )
                db.commit()
                session.clear()
                session["user_id"] = cur.lastrowid
                flash("Welcome to JoyShop! Your account is ready.", "success")
                return redirect(url_for("shop"))
    return render_template("auth.html", mode="signup")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['name'].split()[0]}!", "success")
            return redirect(url_for("index"))
        flash("The email or password you entered is incorrect.", "danger")
    return render_template("auth.html", mode="login")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/shop")
@login_required
def shop():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    category = request.args.get("category", "All")
    search = request.args.get("q", "").strip()
    sql = "SELECT * FROM products WHERE active = 1"
    params = []
    if category != "All":
        sql += " AND category = ?"
        params.append(category)
    if search:
        sql += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    sql += " ORDER BY created_at DESC, id DESC"
    products = get_db().execute(sql, params).fetchall()
    categories = ["All", "Bags", "Shoes", "Clothing", "Accessories"]
    return render_template("shop.html", products=products, categories=categories, category=category, search=search)


def get_cart():
    return session.get("cart", {})


def cart_details():
    cart = get_cart()
    if not cart:
        return [], 0
    ids = [int(pid) for pid in cart.keys()]
    placeholders = ",".join("?" for _ in ids)
    rows = get_db().execute(
        f"SELECT * FROM products WHERE id IN ({placeholders}) AND active = 1", ids
    ).fetchall()
    items, total = [], 0
    for product in rows:
        qty = int(cart.get(str(product["id"]), 0))
        if qty > 0:
            subtotal = product["price"] * qty
            items.append({"product": product, "quantity": qty, "subtotal": subtotal})
            total += subtotal
    return items, total


@app.post("/cart/add/<int:product_id>")
@login_required
def add_to_cart(product_id):
    product = get_db().execute("SELECT * FROM products WHERE id=? AND active=1", (product_id,)).fetchone()
    if not product:
        abort(404)
    cart = get_cart()
    key = str(product_id)
    new_qty = int(cart.get(key, 0)) + 1
    if new_qty > product["stock"]:
        flash("That item has no more available stock.", "warning")
    else:
        cart[key] = new_qty
        session["cart"] = cart
        flash(f"{product['name']} added to your cart.", "success")
    return redirect(request.referrer or url_for("shop"))


@app.route("/cart")
@login_required
def cart():
    items, total = cart_details()
    return render_template("cart.html", items=items, total=total)


@app.post("/cart/update")
@login_required
def update_cart():
    cart_data = get_cart()
    for key in list(cart_data.keys()):
        try:
            qty = int(request.form.get(f"qty_{key}", 0))
        except ValueError:
            qty = 0
        product = get_db().execute("SELECT stock FROM products WHERE id=?", (int(key),)).fetchone()
        if qty <= 0 or not product:
            cart_data.pop(key, None)
        else:
            cart_data[key] = min(qty, product["stock"])
    session["cart"] = cart_data
    flash("Your cart has been updated.", "success")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    items, total = cart_details()
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("cart"))
    if request.method == "GET":
        return render_template("checkout.html", items=items, total=total)

    name = request.form.get("full_name", "").strip()
    phone = request.form.get("phone", "").strip()
    address = request.form.get("address", "").strip()
    barangay = request.form.get("barangay", "").strip()
    city = request.form.get("city", "").strip()
    province = request.form.get("province", "").strip()
    postal_code = request.form.get("postal_code", "").strip()
    payment_method = request.form.get("payment_method", "COD").strip().upper()
    payment_note = request.form.get("payment_note", "").strip()
    if not all([name, phone, address, barangay, city, province]):
        flash("Please complete all required delivery details.", "warning")
        return redirect(url_for("checkout"))
    if payment_method not in {"COD", "GCASH", "MAYA"}:
        flash("Please choose a valid payment method.", "warning")
        return redirect(url_for("checkout"))
    if payment_method in {"GCASH", "MAYA"} and not payment_note:
        flash("For this prototype, enter the account name or payment reference note.", "warning")
        return redirect(url_for("checkout"))

    full_address = f"{name}, {phone}, {address}, Barangay {barangay}, {city}, {province} {postal_code}".strip()
    db = get_db()
    try:
        for item in items:
            current = db.execute("SELECT stock FROM products WHERE id=?", (item["product"]["id"],)).fetchone()
            if not current or current["stock"] < item["quantity"]:
                raise ValueError(f"Not enough stock for {item['product']['name']}. Please update your cart.")
        status = "Payment Review" if payment_method in {"GCASH", "MAYA"} else "Processing"
        cur = db.execute(
            "INSERT INTO orders (user_id,total,status,created_at,phone,address,payment_method,payment_note) VALUES (?,?,?,?,?,?,?,?)",
            (g.user["id"], total, status, now(), phone, full_address, payment_method, payment_note)
        )
        order_id = cur.lastrowid
        for item in items:
            product = item["product"]
            db.execute(
                "INSERT INTO order_items (order_id,product_id,product_name,unit_price,quantity) VALUES (?,?,?,?,?)",
                (order_id, product["id"], product["name"], product["price"], item["quantity"])
            )
            db.execute("UPDATE products SET stock=stock-? WHERE id=?", (item["quantity"], product["id"]))
        db.commit()
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "warning")
        return redirect(url_for("cart"))
    session["cart"] = {}
    flash("Prototype order submitted! No real payment was collected.", "success")
    return redirect(url_for("my_orders"))

@app.route("/my-orders")
@login_required
def my_orders():
    orders = get_db().execute(
        "SELECT * FROM orders WHERE user_id=? AND customer_hidden=0 ORDER BY id DESC", (g.user["id"],)
    ).fetchall()
    order_items = {}
    for order in orders:
        order_items[order["id"]] = get_db().execute(
            "SELECT * FROM order_items WHERE order_id=?", (order["id"],)
        ).fetchall()
    return render_template("my_orders.html", orders=orders, order_items=order_items)


@app.post("/my-orders/<int:order_id>/remove")
@login_required
def hide_customer_order(order_id):
    db = get_db()
    order = db.execute(
        "SELECT id,status FROM orders WHERE id=? AND user_id=?", (order_id, g.user["id"])
    ).fetchone()
    if not order:
        abort(404)
    if order["status"] not in {"Completed", "Cancelled"}:
        flash("Only completed or cancelled orders can be removed from your order history.", "warning")
    else:
        db.execute("UPDATE orders SET customer_hidden=1 WHERE id=?", (order_id,))
        db.commit()
        flash("Order removed from your order history.", "success")
    return redirect(url_for("my_orders"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "products": db.execute("SELECT COUNT(*) n FROM products WHERE active=1").fetchone()["n"],
        "orders": db.execute("SELECT COUNT(*) n FROM orders").fetchone()["n"],
        "customers": db.execute("SELECT COUNT(*) n FROM users WHERE role='customer'").fetchone()["n"],
        "sales": db.execute("SELECT COALESCE(SUM(total),0) n FROM orders WHERE status != 'Cancelled'").fetchone()["n"],
    }
    recent = db.execute("""
        SELECT orders.*, users.name customer_name, users.email
        FROM orders JOIN users ON users.id=orders.user_id
        ORDER BY orders.id DESC LIMIT 6
    """).fetchall()
    return render_template("admin_dashboard.html", stats=stats, recent=recent)


@app.route("/admin/products")
@admin_required
def admin_products():
    products = get_db().execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    return render_template("admin_products.html", products=products, product=None)


@app.route("/admin/products/new", methods=["GET", "POST"])
@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_required
def product_form(product_id=None):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone() if product_id else None
    if product_id and not product:
        abort(404)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "")
        description = request.form.get("description", "").strip()
        emoji = request.form.get("emoji", "🛍️").strip()[:8] or "🛍️"
        try:
            price = float(request.form.get("price", "0"))
            stock = int(request.form.get("stock", "0"))
        except ValueError:
            price, stock = -1, -1
        if not name or category not in ["Bags", "Shoes", "Clothing", "Accessories"] or price < 0 or stock < 0:
            flash("Please provide valid product details.", "danger")
        elif product:
            db.execute(
                "UPDATE products SET name=?,category=?,description=?,price=?,stock=?,emoji=? WHERE id=?",
                (name, category, description, price, stock, emoji, product_id)
            )
            db.commit()
            flash("Product updated successfully.", "success")
            return redirect(url_for("admin_products"))
        else:
            db.execute(
                "INSERT INTO products (name,category,description,price,stock,emoji,created_at) VALUES (?,?,?,?,?,?,?)",
                (name, category, description, price, stock, emoji, now())
            )
            db.commit()
            flash("Product added successfully.", "success")
            return redirect(url_for("admin_products"))
    return render_template("product_form.html", product=product)


@app.post("/admin/products/<int:product_id>/delete")
@admin_required
def delete_product(product_id):
    get_db().execute("UPDATE products SET active=0 WHERE id=?", (product_id,))
    get_db().commit()
    flash("Product removed from the shop.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = get_db().execute("""
        SELECT orders.*, users.name customer_name, users.email
        FROM orders JOIN users ON users.id=orders.user_id
        WHERE orders.admin_hidden=0
        ORDER BY orders.id DESC
    """).fetchall()
    return render_template("admin_orders.html", orders=orders)


@app.post("/admin/orders/<int:order_id>/status")
@admin_required
def update_order_status(order_id):
    status = request.form.get("status")
    allowed = ["Processing", "Shipped", "Completed", "Cancelled"]
    if status not in allowed:
        abort(400)
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        abort(404)
    old_status = order["status"]
    if status == "Cancelled" and old_status != "Cancelled":
        items = db.execute("SELECT product_id,quantity FROM order_items WHERE order_id=?", (order_id,)).fetchall()
        for item in items:
            if item["product_id"]:
                db.execute("UPDATE products SET stock=stock+? WHERE id=?", (item["quantity"], item["product_id"]))
    elif old_status == "Cancelled" and status != "Cancelled":
        items = db.execute("SELECT product_id,quantity FROM order_items WHERE order_id=?", (order_id,)).fetchall()
        for item in items:
            if item["product_id"]:
                product = db.execute("SELECT stock FROM products WHERE id=?", (item["product_id"],)).fetchone()
                if not product or product["stock"] < item["quantity"]:
                    flash("Cannot reactivate this order because an item is out of stock.", "warning")
                    return redirect(url_for("admin_orders"))
        for item in items:
            if item["product_id"]:
                db.execute("UPDATE products SET stock=stock-? WHERE id=?", (item["quantity"], item["product_id"]))
    db.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    db.commit()
    flash("Order status updated.", "success")
    return redirect(url_for("admin_orders"))


@app.post("/admin/orders/<int:order_id>/remove")
@admin_required
def hide_admin_order(order_id):
    db = get_db()
    order = db.execute("SELECT id,status FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        abort(404)
    if order["status"] not in {"Completed", "Cancelled"}:
        flash("Only completed or cancelled orders can be removed from the admin order list.", "warning")
    else:
        db.execute("UPDATE orders SET admin_hidden=1 WHERE id=?", (order_id,))
        db.commit()
        flash("Order removed from the admin order list.", "success")
    return redirect(url_for("admin_orders"))


@app.route("/admin/customers")
@admin_required
def admin_customers():
    customers = get_db().execute("""
        SELECT users.id,users.name,users.email,users.created_at,COUNT(orders.id) order_count
        FROM users LEFT JOIN orders ON orders.user_id=users.id
        WHERE users.role='customer'
        GROUP BY users.id ORDER BY users.id DESC
    """).fetchall()
    return render_template("admin_customers.html", customers=customers)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn't find that page."), 404


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=os.environ.get("FLASK_DEBUG") == "1")
