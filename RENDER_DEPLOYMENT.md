# Render Deployment Guide for CiteCraft

This guide will help you deploy CiteCraft to Render.

## Prerequisites

1. A GitHub account with your code pushed to a repository
2. A Render account (sign up at https://render.com)

## Deployment Steps

### 1. Create a PostgreSQL Database on Render

1. Go to your Render dashboard
2. Click "New +" → "PostgreSQL"
3. Configure:
   - **Name**: `citecraft-db` (or your preferred name)
   - **Database**: `citecraft`
   - **User**: `citecraft`
   - **Region**: Choose closest to your users
   - **Plan**: Free tier is fine for testing
4. Click "Create Database"
5. **Important**: Copy the **Internal Database URL** - you'll need this later

### 2. Create a Web Service

1. In Render dashboard, click "New +" → "Web Service"
2. Connect your GitHub repository
3. Configure the service:
   - **Name**: `citecraft` (or your preferred name)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free tier is fine for testing

### 3. Configure Environment Variables

In your Web Service settings, add these environment variables:

- **DATABASE_URL**: Paste the Internal Database URL from your PostgreSQL database
- **SESSION_SECRET**: Generate a random secret key (you can use: `python -c "import secrets; print(secrets.token_hex(32))"`)
- **FLASK_ENV**: `production` (or leave empty for production mode)

### 4. Deploy

1. Click "Create Web Service"
2. Render will automatically:
   - Clone your repository
   - Install dependencies
   - Build your application
   - Start the service

### 5. Verify Deployment

1. Wait for the build to complete (usually 2-5 minutes)
2. Check the logs for any errors
3. Visit your service URL (provided by Render)
4. You should see the CiteCraft homepage

## Using render.yaml (Alternative Method)

If you prefer using the `render.yaml` file:

1. Push `render.yaml` to your repository
2. In Render dashboard, click "New +" → "Blueprint"
3. Connect your repository
4. Render will automatically detect and use `render.yaml`
5. Review the configuration and click "Apply"

## Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `SESSION_SECRET` | Secret key for session encryption | Yes |
| `FLASK_ENV` | Flask environment (production/development) | No |
| `PORT` | Port number (auto-set by Render) | No |

## Troubleshooting

### Database Connection Issues

- Ensure `DATABASE_URL` uses the **Internal Database URL** (not External)
- Check that the database is in the same region as your web service
- Verify `psycopg2-binary` is in `requirements.txt`

### Build Failures

- Check that all dependencies are in `requirements.txt`
- Verify Python version compatibility
- Check build logs for specific error messages

### Application Errors

- Check the service logs in Render dashboard
- Verify all environment variables are set correctly
- Ensure the database is running and accessible

## Local Development vs Production

- **Local**: Uses SQLite database (`research_platform.db`)
- **Production**: Uses PostgreSQL (configured via `DATABASE_URL`)

The application automatically detects the environment and uses the appropriate database.

## Notes

- Free tier services on Render spin down after 15 minutes of inactivity
- First request after spin-down may take 30-60 seconds
- Consider upgrading to a paid plan for production use
- Database backups are recommended for production deployments

## Support

For issues specific to:
- **Render**: Check Render documentation at https://render.com/docs
- **CiteCraft**: Check the main README.md file

