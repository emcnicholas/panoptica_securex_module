FROM python:3.10-alpine

# Setting an environment variable with the directory
# where we will be running the app
ENV APP /app

# Creating a directory and instructing Docker to work on this from now on
RUN mkdir $APP
WORKDIR $APP

# Exposing the port for Gunicorn
EXPOSE 5000

# Copying requirements to the APP directory in order to install the required libs
COPY requirements.txt .
RUN apk update && \
    apk add --update alpine-sdk && \
    apk add --virtual build-deps gcc python3-dev musl-dev && \
    apk add --no-cache bash && \
    apk add --no-cache nano  &&\
    python3 -m pip install -r requirements.txt --no-cache-dir && \
   adduser \
      --disabled-password \
      --no-create-home \
      django-user



# Copying rest of the code to WORKDIR
COPY . .

# Finally, run the app with Gunicorn command
CMD [ "gunicorn", "-c", "gunicorn.conf.py", "wsgi:app" ]
