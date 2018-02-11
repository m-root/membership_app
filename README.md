# membership_app
A membership App.






TODO: Running the requests using celery from the background

# Install

### Start celery beat
```
    celery -A payload beat --loglevel=INFO
```


### Start celery worker
```
        celery -A payload worker --loglevel=INFO
```