#/bin/sh

# Install google-cloud-pubsub module
echo "Installing google-cloud-pubsub python module..."
pip install --upgrade google-cloud-pubsub

# Set service account json environment variable
SERVICE_ACCOUNT_FILE_LOCATION=$1
echo "Setting GOOGLE_APPLICATION_CREDENTIALS to $SERVICE_ACCOUNT_FILE_LOCATION"
export GOOGLE_APPLICATION_CREDENTIALS="$SERVICE_ACCOUNT_FILE_LOCATION"

echo "Setup complete"