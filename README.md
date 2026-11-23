# College Board System (CBS) - Digital Institutional Notice Platform

> Developed based on the **Software Engineering Project Report (Version 1.0)** & **Role-Based Login & User Management System Specification**.

---

## 🏛️ System Overview

The **College Board System (CBS)** is an institutional, role-based digital notice board and authentication platform designed to replace physical paper notice boards and fragmented messaging channels.

It incorporates a secure, centralized **Four-Tier Role-Based Authentication & Access Control System**:
1. **Principal (Administrator)**: Executive authority overseeing institutional accounts, notices, audit trails, and master data.
2. **Head of Department (HOD)**: Departmental authority reviewing faculty announcement queues and publishing department circulars.
3. **Faculty**: Academic authoring notices with multi-file attachments, targeting specific student cohorts, and tracking verified read receipts.
4. **Student**: Recipient of targeted announcements, urgent alerts, and verified readership logging.

---

## 🔑 New Login Credentials & Role Directory Page

A dedicated, standalone **Institutional Login Credentials & Role Directory** page is now available:
- **Direct File**: [`credentials.html`](file:///e:/duplicate/credentials.html)
- **Local Server URL**: `http://localhost:8080/credentials.html`
- **Attached Campus Photo**: Features the high-resolution campus building photograph (`campus_bg.jpg`) in a prominent hero banner.
- **Interactive Quick-Fill & Direct Sign-In**: Click any *"Sign In as [Role]"* or *"Fill Login Form"* button on `credentials.html` to test that role instantly in `index.html`.
- **Copy Buttons**: 1-click clipboard copy for User IDs, emails, and passwords with interactive toast feedback.
- **RBAC Matrix Table**: Complete permission breakdown comparing Principal, HOD, Faculty, and Student privileges.

---

## 👥 Seed Test Accounts & Credentials Matrix

Users can authenticate using either their **User ID / Roll No / Employee ID** OR their **Institutional Email**:

| Role | User Name | User ID / Roll / Emp ID | Institutional Email | Default Password | Capabilities & Scope |
|---|---|---|---|---|---|
| **Principal (Admin)** | Dr. V. Ramanathan | `PRIN-001` | `principal@college.edu` | `Password@123` | Full admin control, create/view/edit/deactivate accounts, reset passwords, audit logs, scheduler, master data |
| **Legacy Admin** | System Administrator | `ADM-001` | `admin@college.edu` | `Password@123` | Central IT Administrator alias with Principal privileges |
| **HOD** | Dr. K. Prasad | `HOD-CSE-001` | `k.prasad@college.edu` | `Password@123` | CSE Approval Queue review, approve/reject notices with remarks, direct department circular publication |
| **Faculty** | Dr. Anitha Reddy | `FAC-CSE-003` | `anitha.reddy@college.edu` | `Password@123` | Author notices with attachments, target dept/year/sec, inspect verified reader log timestamps |
| **Faculty (Alt)** | Dr. S. Rao | `FAC-CSE-004` | `s.rao@college.edu` | `Password@123` | Author notices, draft announcements, track student read counts |
| **Student** | Ravi Kumar | `24CS108` | `ravi.kumar@college.edu` | `Password@123` | Targeted notices for CSE III Year Sec A, urgent banners, attachment lightbox previews, mark-read log |
| **Student (Alt)** | Sneha Patel | `24IT042` | `sneha.patel@college.edu` | `Password@123` | Targeted notices for IT III Year Sec B |
| **First-Login Demo** | Vikram Verma | `24CS199` | `newstudent@college.edu` | `Temp#2026!` | **Demonstrates Requirement 6**: Prompts mandatory password change dialog upon initial login |

---

## 🛡️ Security Implementation & Requirements Compliance

### 1. Modern Login System (Requirement 1)
- Modern split-screen layout featuring the attached campus photograph (`campus_bg.jpg`) on the left and high-contrast login card on the right.
- Dual authentication input: supports **User ID / Roll No / Employee ID** OR **Email Address**.
- Show/hide password visibility toggle (`👁️`).
- Quick Persona Selector chips for instant 1-click test credential population.
- Automatic redirection to the user's role-specific dashboard upon sign-in.
- Navbar Sign-Out button (`🚪 Logout`) and Role Quick Switcher for seamless testing.

### 2. Principal Administration (Requirement 2)
- Exclusive administrative access for the Principal to:
  - **Create User**: Full modal with role-specific fields and validation.
  - **View Profile**: Comprehensive read-only profile card displaying security metadata, hashing status, first-login flag, and failed attempts.
  - **Edit User**: Modify name, email, department, role, roll/emp ID, year/section/designation, phone, and active status.
  - **Activate / Deactivate**: Direct status toggle preventing deactivated users from signing in. (Principal cannot deactivate their own session).
  - **Reset Password**: Principal can issue a temporary password, force first-login change, and clear lockouts.
  - **Delete Account**: Safe deletion with confirmation (cannot delete self).
  - **Filter & Search**: Live search by name/email/ID, filter by Role, Department, and Status.
  - **CSV Export**: Export full user directory as a downloadable CSV.

### 3. Strict Account Creation (Requirement 3)
- **Mandatory Field Validation**: Full Name, Institutional Email, Role, Department, Roll No or Employee ID, and Password.
- **Unique Identifier Enforcement**: Roll numbers and Employee IDs are strictly checked against all existing accounts.
- **Email Regex & Duplicate Check**: Enforces valid RFC email pattern and guarantees no duplicate emails.
- **Strong Password Rules**: Must contain at least 8 characters, 1 uppercase letter (`A-Z`), 1 lowercase letter (`a-z`), 1 numeric digit (`0-9`), and 1 special symbol (`!@#$%^&*...`).
- **Interactive Helper**: "Auto-Generate Strong Password" generates compliant passwords (`Col@2026!Univ`).
- **Authorization Guard**: Any non-Principal attempt to create an account is blocked with an alert and logged to the audit trail.

### 4. Role-Based Dashboards & Permissions (Requirement 4)
- **Student Dashboard**: Filtered to student's department and year. Search, category chips, urgent notice banner, single-read verification logging, and attachment lightbox.
- **Faculty Dashboard**: My notices table (Draft, Pending, Active, Rejected), create notice form, reader log verification modal (TC-25).
- **HOD Dashboard**: Department notices overview, split-screen Approval Queue (approve/reject with mandatory remarks), direct circular posting.
- **Principal Dashboard**: Executive control hub, KPI statistics, global announcements, manual scheduler trigger, user management, master data, reports, and audit trail.
- **Backend Route Authorization**: Non-authorized tab access (e.g. Student trying to view user management or audit logs) is blocked with an access-denied toast and security audit event.

### 5. Security Architecture (Requirement 5)
- **Password Hashing**: Passwords salted and hashed with **SHA-256** before storage.
- **Brute-Force Protection**: 5 consecutive failed login attempts trigger an automatic **60-second lockout cooldown**. Countdown timer displayed to the user.
- **Session Management**: Session state stored in `localStorage` (`CBS_SESSION_USER_ID`) with safe initialization, unauthenticated guest state, and explicit sign-out.
- **Self-Service Password Reset**: "Forgot Password?" generates a temporary password and flags account for mandatory first-login password change.
- **Deactivated Account Guard**: Deactivated accounts are blocked at authentication with administrative audit logging.

### 6. Mandatory First-Login Password Change (Requirement 6)
- New accounts created by the Principal or accounts issued temporary passwords have `is_first_login = true`.
- Upon sign-in, user is presented with a non-dismissible **Password Change Required** modal.
- Includes a **live interactive password requirements checklist** with dynamic checkmarks and color-coded strength bar.
- Blocks access to the dashboard until a strong permanent password is set and confirmed.
- Tested out-of-the-box using the demo account: `newstudent@college.edu` (`Temp#2026!`).

### 7. Immutable Audit Logs (Requirement 7)
- Automatically captures all security and administrative events:
  - `USER_ADD`: Account creation by Principal
  - `USER_EDIT`: Profile modification
  - `USER_STATUS_CHANGE`: Account activation/deactivation
  - `PASSWORD_RESET_ADMIN`: Administrative password reset by Principal
  - `PASSWORD_RESET_SELF`: Self-service temporary password issuance
  - `PASSWORD_CHANGE_FIRST_LOGIN`: First-time password update completion
  - `LOGIN` & `LOGOUT`: Session events
  - `LOGIN_FAILED`: Failed login attempt with remaining attempt counter
  - `LOGIN_LOCKOUT`: 60-second lockout triggered after 5 failed attempts
  - `UNAUTHORIZED_ACCESS_BLOCKED`: Blocked access attempts
- Filterable by Category (`All`, `User Lifecycle`, `Authentication & Passwords`, `Notice Workflow`, `System & Scheduler`).
- Searchable by actor, action, and details.
- "Export Audit Log CSV" button.

### 8. Professional Responsive UI (Requirement 8)
- Translucent frosted glass containers (`backdrop-filter: blur()`).
- High-contrast, WCAG-compliant color schemes and responsive layouts for desktop, tablet, and mobile.
- Clean notifications drawer, urgent alerts banner, and animated toast notifications.

---

## 🚀 How to Run and Test

### Option 1: Direct Browser Launch
Open `index.html` or `credentials.html` in Google Chrome, Microsoft Edge, or Firefox:
```powershell
Start-Process "index.html"
```

### Option 2: Lightweight Local Web Server
Run the included PowerShell HTTP server:
```powershell
powershell -ExecutionPolicy Bypass -File .\start_server.ps1
```
- Main Portal & Login: **`http://localhost:8080/`**
- Login Credentials Directory: **`http://localhost:8080/credentials.html`**

---

## 🧪 Quick Test Scenarios

1. **Test Standard Role Login**:
   - Go to `http://localhost:8080/`
   - Click the *"🛡️ Principal"* quick pill or enter `principal@college.edu` / `Password@123`
   - Observe automatic redirect to the Principal Control Hub.
   - Click *"User Management"* tab to test editing, deactivating, or creating users.
   - Click *"🚪 Logout"* in the navbar to return to the login screen.

2. **Test First-Login Password Change (Requirement 6)**:
   - On the login screen, click the *"🔑 First Login"* quick pill or enter `newstudent@college.edu` / `Temp#2026!`
   - Click *"Sign In to Dashboard"*.
   - Observe the mandatory First-Login Password Change dialog.
   - Enter a new strong password (e.g. `Student@2026!`) and observe the live requirement checkmarks turn green.
   - Submit and verify that the permanent password is saved and the Student Dashboard loads.

3. **Test 5-Attempt Lockout (Requirement 5)**:
   - On the login screen, enter an incorrect password 5 times.
   - Observe the warning showing remaining attempts (`4 remaining`, `3 remaining`...).
   - On the 5th attempt, observe the 60-second security cooldown lockout message.

4. **Test Route Authorization (Requirement 4)**:
   - Log in as Student Ravi Kumar (`24CS108` / `Password@123`).
   - Notice that administrative tabs (`User Management`, `Master Data`, `Audit Log`) are completely hidden.
   - If attempting to call `cbsApp.switchTab('users')` from console, observe the urgent access-denied toast and security audit event.

5. **Test Principal Administration (Requirements 2 & 3)**:
   - Log in as Principal (`principal@college.edu`).
   - Go to *"User Management"*.
   - Click *"+ Create User Account"*: enter duplicate email or roll number to verify validation blocks it; create a valid account and verify it appears in the table.
   - Click *"🔑 Reset"* on any user: issue a temporary password and check that `is_first_login` is flagged.
   - Click *"⛔ Deact"* to deactivate a user; try logging in with that user to verify the deactivation guard blocks entry.
   - Go to *"System Audit Log"* and observe every one of these actions recorded with timestamp and IP.

---

## 📂 Project Structure

```
e:\duplicate\
├── index.html          # Main application page with role layouts, login view & modals
├── credentials.html    # Dedicated Role-Based Credentials Directory with campus photo hero
├── styles.css          # Glassmorphism styling, tokens, login & responsive stylesheet
├── app.js              # State manager, crypto hashing, RBAC workflows & UI controller
├── campus_bg.jpg       # Attached campus main building photograph
├── campus_building.jpg # Architectural photo reference
├── 1.png - 15.png      # Event posters & notice attachments
├── start_server.ps1    # PowerShell web server for localhost:8080
└── README.md           # Documentation, specifications & test guide
```
