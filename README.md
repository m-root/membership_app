# membership_app
A membership App.








# Install

### Edit the settings file by adding your own parameters
```
   SECRET_KEY = ''

    EMAIL_HOST = ''
    EMAIL_PORT = 587
    EMAIL_HOST_USER = ''
    EMAIL_HOST_PASSWORD = ''
    EMAIL_USE_TLS = True

    AFRICASTALKING_USERNAME = ""
    AFRICASTALKING_APIKEY = ""


    GOOGLE_URL_APIKEY = ''




```


### Running the project
```
        git clone https://github.com/m-root/membership_app.git

        cd into dir

        python manage.py makemigrations

        python manage.py migrate

        run: virtualenv venv in your shell.

        run: pip install -r requirements.txt in your shell.

        python manage.py runserver


```



# For running background tasks using celery like sending emails, converting url using google url services and sms with the help of REDIS or RabbitMQ #TODO: Running the requests using celery from the background
### Start celery beat
```
    celery -A payload beat --loglevel=INFO
```


### Start celery worker
```
        celery -A payload worker --loglevel=INFO
```