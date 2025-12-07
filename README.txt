# Pandemic Resilience System

A full-stack web application designed to help manage critical resources, vaccination records, and user purchases during pandemics. Supports three distinct user roles with tailored dashboards and functionality.

---

## How to Run

1. Start MongoDB  
   Default URI: `mongodb://localhost:27017/`  
   (or configure via `.env` file with `MONGO_URI`)

2. Install Dependencies
   pip install -r requirements.txt

3. Start Flask Backend
   python app.py

4. Visit in Browser
   http://localhost:5000

## User Roles & Dashboards

======Government Admin (/admin)===========
Create, delete, and manage user accounts.

Toggle user account status (enable/disable).

Add and update vaccination records.

Manage all vaccination requests.

View available merchant stocks.

View audit logs of all major actions.

View dashboard statistics & charts.

=========Merchant (/merchant)=============
Manage stock (add, update, delete items).

Set item stock limits and pricing.

Batch update inventory via JSON.

View vaccination records & request updates.

View sales history.

Generate vaccination PDF certificates.

==========Public User (/public)===============
View personal profile & vaccination status.

Request new vaccinations.

Upload vaccination PDF records.

Search for critical items in stock.

Purchase items (subject to stock and restrictions).

View personal purchase history.

Download receipts for purchases.
-----------------------------------------------------

Credentials

Role		Email			Password
Admin		admin@mail.com		123
Merchant	merchant@mail.com	123
Public		user@mail.com		123
----------------------------------------------------
====================Tech Stack=====================
Backend: Flask (Python)

Database: MongoDB (via PyMongo)

Frontend: HTML5, CSS3, JavaScript

Authentication: JWT (JSON Web Tokens)

PDF Generation: ReportLab

Charts: Chart.js

Logging: Python Logging Framework

================Features Summary====================

Role-based access control with JWT authentication.

Secure password hashing (SHA-256).

Audit logging for critical actions.

Merchant stock management with per-item purchase limits.

Vaccination request & approval workflows.

Dynamic PDF generation for receipts and vaccination certificates.

User activity tracking (purchase limits, day-based purchase restrictions).

Mobile responsive UI.


============ File Structure Overview ===================

├── app.py              # Flask backend with routes and logic
├── templates/
│   ├── admin.html
│   ├── merchant.html
│   ├── public.html
│   ├── login.html
│   ├── register.html
├── static/
│   ├── backend.js      # Frontend JavaScript logic
│   ├── style.css       # Stylesheet
├── uploads/            # Vaccination PDFs
├── .env                # Environment variables
└── README.md           # (this file)

=============Security Notes=================================

JWT tokens expire in 24 hours!!!!!
User passwords are hashed using SHA-256 before storage.
Admin-only actions are protected via decorators.
HTTPS redirection is enforced (except in development mode).
Role-specific pages are accessible only with a valid token.

=============================================================