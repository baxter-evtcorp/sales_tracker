# Sales Activity Tracker

A web application for tracking sales activities and managing the MEDDPIC pipeline.

## Features

- Weekly Activity Logging
- MEDDPIC Pipeline Management
- User Authentication
- Settings Management

## Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Update the values in `.env` as needed

4. Initialize the database:
   ```bash
   flask run
   ```
   The database will be automatically created on first run.

5. Start the application:
   ```bash
   flask run
   ```

## API Endpoints

### Authentication
- POST /api/register - Register a new user
- POST /api/login - Login and get JWT token

### Activities
- GET /api/activities - Get all activities
- POST /api/activities - Create a new activity

### Deals
- GET /api/deals - Get all deals
- POST /api/deals - Create a new deal
- PUT /api/deals/{id} - Update a deal
- POST /api/deals/{id}/archive - Archive a deal
- DELETE /api/deals/{id} - Delete a deal

### Settings
- GET /api/settings - Get user settings
- POST /api/settings - Update user settings
