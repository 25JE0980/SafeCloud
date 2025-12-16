# SafeCloud

SafeCloud is a secure cloud-based file storage web application built using Flask and SQLite.

--Features Implemented
  - User signup and login with password hashing
  - Session-Based Authentication
  - Protected Dashboard
  - File Upload System (Design and Basic implementation)

--Tech Stack
  - Python, Flask
  - SQLite
  - HTML (Jinja Templates)

--Files Uploaded by Me
  - app.py:
        - Main Backend file 
        - It contains:
              - Flask app creation
              - Routes
              - Session Handling
              - Database connections
              - File upload logic

  - Templates (Frontend):
     - home.html - Home Page Form
     - signup.html - Signup Page Form
     - login.html - Login Page Form
     - dashboard.html - Dashboard Page Form ( Only for logged-in users )

  - safecloud.db:
            - SQLite Database file 
            - Contains users information and metadata of files 

  - init_db.py:
            - One time Database setup or Database initialization (creates users and files tables)


NOTE:
  **Files uploaded by users are stored in uploads folder. I have not added into my repo as it is empty.**
  
