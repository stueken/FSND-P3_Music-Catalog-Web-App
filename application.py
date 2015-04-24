import os
import random
import string
import httplib2  # A http client library.
# This module provides an API converting inmemory python objects to a
# serialized representation known as JSON.
import json
# Apache2 license http-library written in Python similar to
# urllib2, but with a few improvements.
import requests
from flask import (Flask, render_template, request, redirect, jsonify, url_for,
                   flash)
# To prevent anti-forgery request attacks a unique session token needs to be
# created that the client side returns alongside the Google generated
# authorization code.
# The login_session object works like a dictionary. Values can be stored in it
# for the longevity of a user session with the server.
from flask import session as login_session
# Converts the return value from a function into a real response object that
# can be send off to the client.
from flask import make_response
# SeaSurf is a Flask Extension for preventing cross-site request forgery
# (CSRF).
from flask.ext.seasurf import SeaSurf
# Function to validate filenames in case it is forged.
from werkzeug import secure_filename
# Function to creates a flow object from the clientsecrets-JSON-file. This
# JSON-formatted file stores the client id, client secret and other OAuth2
# parameters.
from oauth2client.client import flow_from_clientsecrets
# This function catches a possible error when trying to exchange an
# authorization code for an access token.
from oauth2client.client import FlowExchangeError
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Collection, Album, User

# Create an instance of the Flask class with the name of the running
# application as the argument.
#
# Anytime an application in Python is run, a special variable called __name__
# gets defined for the application and all the imports it uses.
app = Flask(__name__)

# Protecting the app against CSRF attacks.
csrf = SeaSurf(app)

# Settings for the image upload functionality.
#
# Dynamically determine the root directory.
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
# Folder for the uploaded album cover images.
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'static/uploads')
# Allow only certain file extensions for uploaded images.
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Limit the file upload size to 2 megabytes.
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# Declare client_id for Google authentification by referencing the
# client_secrets file.
CLIENT_ID = json.loads(
    open('g_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Music Collection Application"

# Connect to Database and create a database session.
engine = create_engine('sqlite:///musiccollections.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    """ Render the login page after a random state token is created.

    Creates a random anti-forgery state token with each GET request sent to
    localhost:5000/login before rendering the login page.

    Returns:
        The login page.
    """

    # Create a variable which will be 32 characters long and a mix of uppercase
    # letters and digits.
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    # Store the state token in the login_session object.
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Exempted from SeaSurf-CSRF.method as the showLogin-method creates an own
# CSRF-state token.
@csrf.exempt
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Handles the Google+ sign-in process on the server side.

    Server side function to handle the state-token and the one-time-code
    send from the client callback function following the seven steps of the
    Google+ sign-in flow. See the illustrated flow on
    https://developers.google.com/+/web/signin/server-side-flow.

    Returns:
        When the sign-in was successful, a html response is sent to the client
        signInCallback-function confirming the login. Otherwise, one of the
        following responses is returned:
        200 OK: The user is already connected.
        401 Unauthorized: There is either a mismatch between the sent and
            received state token, the received access token doesn't belong to
            the intended user or the received client id doesn't match the web
            apps client id.
        500 Internal server error: The access token inside the received
            credentials object is not a valid one.

    Raises:
        FlowExchangeError: The exchange of the one-time code for the
            credentials object failed.
    """
    # Confirm that the token the client sends to the server matches the
    # state token that the server sends to the client.
    # This roundship verification helps ensure that the user is making the
    # request and and not a maliciousscript.
    # Using the request.args.get-method, the code examines the state token
    # passed in and compares it to the state of the login session. If thesse
    # two do not match, a response message of an invalid state token is created
    # and returned to the client. No further authentication will occur on the
    # server side if there was a mismatch between these state token.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # If the above statement is not true then I can proceed and collect the
    # one-time code from the server with the request.data-function.
    code = request.data

    # 5) The Server tries to exchange the one-time code for an access_token and
    # an id_token (credentials object).
    # 6) When successful, Google returns the credentials object. Then the
    # server is able to make its own API calls, which can be done while the
    # user is offline.
    try:
        # Create an oauth_flow object and add clients secret key information
        # to it.
        oauth_flow = flow_from_clientsecrets(
            'g_client_secrets.json', scope='')
        # Postmessage specifies that this is the one-time-code flow that my
        # server will be sending off.
        oauth_flow.redirect_uri = 'postmessage'
        # The exchange is initiated with the step2_exchange-function passing in
        # the one-time code as input.
        # The step2_exchange-function of the flow-class exchanges an
        # authorization (one-time) code for an credentials object.
        # If all goes well, the response from Google will be an object which
        # is stored under the name credentials.
        credentials = oauth_flow.step2_exchange(code)
    # If an error happens along the way, then this FlowExchangeError is thrown
    # and sends the response as an JSON-object.
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # After the credentials object has been received. It has to be checked if
    # there is a valid access token inside of it.
    access_token = credentials.access_token
    # If the token is appended to the following url, the Google API server can
    # verify that this is a valid token for use.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Create a JSON get-request containing the url and access-token and store
    # the result of this request in a variable called result
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, send a 500 internal
    # server error is send to the client.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # If the above if-statement isn't true then the access token is working.

    # Next, verify that the access token is used for the intended user.
    # Grab the id of the token in my credentials object and compare it to the
    # id returned by the google api server. If these two ids do not match, then
    # I do not have the correct token and should return an error.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Similary, if the client ids do not match, then my app is trying to use a
    # client_id that doesn't belong to it. So I shouldn't allow for this.
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check if the user is already logged in
    # ! Credentials shouldn't been stored in the session
    # stored_credentials = login_session.get('credentials')
    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
    # So assuming that none of these if-statements were true, I have a valid
    # access token and my user is successfully able to login to my server.
    # In this user's login_session, the credentials and the gplus_id are stored
    # to recall later (see check above).
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Use the google plus API to get some more information about the user.
    # Here, a message is send off to the google API server with the access
    # token requesting the user info allowed by the token scope and store it in
    # an object called data.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # Data should have all of the values listed on
    # https://developers.google.com/+/api/openidconnect/getOpenIdConnect#response
    # filled in, so long as the user specified them in their account. In the
    # following, the users name, picture and e-mail address are stored in the
    # login session.
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # If user doesn't exist, make a new one.
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # 7) If the above worked, a html response is returned confirming the login
    # to the Client.
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px; border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route("/gdisconnect")
def gdisconnect():
    """ Revoke a current user's token and reset their login_session.

    This function is called from the disconnect method when the user is logged
    in with Google+.

    Returns:
        200 OK: When user is successfully disconnected or currently not
            connected.
        400 Bad Request: When the given token was invalid.
    """

    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user is not connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Execute HTTP GET request to revoke current token.
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        response = make_response(
            json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Exempted from SeaSurf-CSRF-method as the showLogin-method creates an own
# CSRF-state token.
@csrf.exempt
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """ Handles the Facebook sign-in process on the server side.

    Read the login flow step by step on
    https://developers.facebook.com/docs/facebook-login/login-flow-for-web/v2.2.

    Returns:
        When the sign-in was successful, a html response is sent to the client
        sendTokenToServer-function confirming the login. Otherwise, the
        following response is returned:
        401 Unauthorized: There is a mismatch between the sent and
            received state token.
    """
    # Similarily to the Google login, the value of the state token is verified
    # to protect against cross-site reference forgery attacks.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Exchange client token for long-lived server-side token with GET
    # /oauth/access_token?grant_type=fb_exchange_token&client_id={app-id}
    # &client_secret={app-secret}&fb_exchange_token={short-lived-token}.
    access_token = request.data
    app_id = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = ("https://graph.facebook.com/oauth/access_token?grant_type="
           "fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token="
           "%s" % (app_id, app_secret, access_token))
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    # not used: userinfo_url = "https://graph.facebook.com/v2.2/me"

    # The long-lived token includes an expires-field that indicates how long
    # this token is valid. Longterm tokens can last up to two months.
    # Strip expire tag from access token since it is not needed to make API
    # calls.
    token = result.split("&")[0]

    # If the token works API calls should be possible like in the following.
    url = 'https://graph.facebook.com/v2.2/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    # Populate the login session.
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    # Facebook uses a separate API call to retrieve a profile picture. So this
    # call is made separetely. The login_session is then populated with the url
    # for the users profile picture.
    url = ('https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&'
           'height=200&width=200' % token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data["data"]["url"]

    # If user doesn't exist, make a new one.
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # If the above worked, a html response is returned confirming the login
    # to the Client.
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += '" style = "width: 300px; height: 300px; border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


# function not used currently
# @app.route("/fbdisconnect")
# def fbdisconnect():
#     facebook_id = login_session['facebook_id']
#     # Execute HTTP GET request to revoke current token.
#     url = 'https://graph.facebook.com/%s/permissions' % facebook_id
#     h = httplib2.Http()
#     result = h.request(url, 'DELETE')[1]
#     return "You have been logged out."


@app.route('/disconnect')
def disconnect():
    """ Deletes all user session values and redirect to the main page."""

    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            # not used: fbdisconnect()
            del login_session['facebook_id']
        # Reset the user's session.
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('indexCollections'))
    else:
        flash("You were not logged in")
        return redirect(url_for('indexCollections'))


# JSON APIs to view Collection Information
@app.route('/collection/JSON')
def collectionsJSON():
    """ Returns all collections in JSON format. """
    collections = session.query(Collection).all()
    return jsonify(Collections=[c.serialize for c in collections])


@app.route('/collection/<int:collection_id>/album/JSON')
def collectionJSON(collection_id):
    """ Returns all albums of a distinct collection in JSON format. """
    # not used: collection = session.query(Collection).filter_by(
    #               id=collection_id).one()
    albums = session.query(Album).filter_by(
        collection_id=collection_id).all()
    return jsonify(Albums=[a.serialize for a in albums])


@app.route('/collection/<int:collection_id>/album/<int:album_id>/JSON')
def albumJSON(collection_id, album_id):
    """ Returns a distinct album in JSON format """
    album = session.query(Album).filter_by(id=album_id).one()
    return jsonify(album=album.serialize)


# ATOM APIs to view Collection Information
@app.route('/collection/atom')
def collectionsATOM():
    """ Returns all collections in Atom format. """
    collections = session.query(Collection).all()
    return render_template('collections.xml', collections=collections)


@app.route('/collection/<int:collection_id>/album/atom')
def collectionATOM(collection_id):
    """ Returns all albums of a distinct collection in Atom format. """
    collection = session.query(Collection).filter_by(id=collection_id).one()
    albums = session.query(Album).filter_by(
        collection_id=collection_id).all()
    return render_template('albums.xml', albums=albums,
                           collection=collection)


@app.route('/collection/<int:collection_id>/album/<int:album_id>/atom')
def albumATOM(collection_id, album_id):
    """ Returns a distinct album in Atom format """
    album = session.query(Album).filter_by(id=album_id).one()
    return render_template('album.xml', album=album)


# The decorator '@' actually wraps the following function inside the
# app.route-function that flask has already created. So if either of these
# routes get sent from the browser the following function gets executed.
# decorators in python can be stacked one on top of the other, so
# @app.rout('/') will call the @app.rout('/hello'), which will call the
# HelloWorld-function. This is useful for having different urls all route to
# the same place.

@app.route('/')
@app.route('/collection/')
def indexCollections():
    """ Show all music collections in the database. """

    collections = session.query(Collection).order_by(asc(Collection.name))
    if 'username' not in login_session:
        return render_template('publicCollections.html',
                               collections=collections)
    else:
        return render_template('indexCollections.html',
                               collections=collections)


@app.route('/collection/new/', methods=['GET', 'POST'])
def newCollection():
    """ Create a new music collection in the database.

    Returns:
        on GET: Page to create a new collection.
        on POST: Redirect to main page after collection has been created.
        Login page when user is not signed in.
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCollection = Collection(name=request.form['name'],
                                   user_id=login_session['user_id'])
        session.add(newCollection)
        flash('New Collection %s Successfully Created' % newCollection.name)
        session.commit()
        return redirect(url_for('indexCollections'))
    else:
        return render_template('newCollection.html')


@app.route('/collection/<int:collection_id>/edit/', methods=['GET', 'POST'])
def editCollection(collection_id):
    """ Edit a music collection in the database.

    Args:
        collection_id: An integer identifying a distinct collection.

    Returns:
        on GET: Page to edit a collection.
        on POST: Redirect to main page after collection has been edited.
        Login page when user is not signed in.
        Alert when user is trying to edit a collection he is not authorized to.
    """
    editedCollection = session.query(Collection).filter_by(
        id=collection_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if editedCollection.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to edit this collection. Please create your own collection in"
                " order to edit.');}</script><body onload='myFunction()'>")
    if request.method == 'POST':
        if request.form['name']:
            editedCollection.name = request.form['name']
            flash('Collection Successfully Edited %s' % editedCollection.name)
            return redirect(url_for('indexCollections'))
    else:
        return render_template('editCollection.html',
                               collection=editedCollection)


@app.route('/collection/<int:collection_id>/delete/', methods=['GET', 'POST'])
def deleteCollection(collection_id):
    """ Delete a music collection in the database.

    Args:
        collection_id: An integer identifying a distinct collection.

    Returns:
        on GET: Page to delete a collection.
        on POST: Redirect to main page after collection has been deleted.
        Login page when user is not signed in.
        Alert when user tries to delete a collection he is not authorized to.
    """
    collectionToDelete = session.query(Collection).filter_by(
        id=collection_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if collectionToDelete.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to delete this collection. Plaease create your own collection"
                " in order to delete.');}</script><body onload='myFunction()'"
                ">")
    if request.method == 'POST':
        session.delete(collectionToDelete)
        flash('%s Successfully Deleted' % collectionToDelete.name)
        session.commit()
        return redirect(url_for('indexCollections',
                                collection_id=collection_id))
    else:
        return render_template('deleteCollection.html',
                               collection=collectionToDelete)


@app.route('/collection/<int:collection_id>/')
@app.route('/collection/<int:collection_id>/album/')
def indexAlbums(collection_id):
    """ Show all albums of a distinct collection.

    Args:
        collection_id: An integer identifying a distinct collection.
    """
    collection = session.query(Collection).filter_by(id=collection_id).one()
    creator = getUserInfo(collection.user_id)
    albums = session.query(Album).filter_by(
        collection_id=collection_id).all()
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template('publicAlbums.html', albums=albums,
                               collection=collection, creator=creator)
    # The logged in user is the creator of the collection.
    else:
        return render_template('indexAlbums.html', albums=albums,
                               collection=collection,
                               creator=creator)


@app.route('/collection/<int:collection_id>/album/new/',
           methods=['GET', 'POST'])
def newAlbum(collection_id):
    """ Create a new album in the database.

    Args:
        collection_id: An integer identifying a distinct collection.

    Returns:
        on GET: Page to create a new album.
        on POST: Redirect to collection page after album has been created.
        Login page when user is not signed in.
        Alert when user is trying to create an album he is not authorized to.
    """
    if 'username' not in login_session:
        return redirect('/login')
    collection = session.query(Collection).filter_by(id=collection_id).one()
    if login_session['user_id'] != collection.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to add albums to this collection. Please create your own "
                "collection in order to add albums.');}</script><body "
                "onload='myFunction()'>")
    if request.method == 'POST':
        source, filename = process_image_source(request.form['image_source'])
        newAlbum = Album(name=request.form['name'],
                         artist=request.form['artist'],
                         genre=request.form['genre'],
                         year=request.form['year'],
                         description=request.form['description'],
                         cover_source=source,
                         cover_image=filename,
                         collection_id=collection_id,
                         user_id=login_session['user_id'])
        session.add(newAlbum)
        session.commit()
        flash('New album %s album Successfully Created' % (newAlbum.name))
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('newAlbum.html', collection_id=collection_id)


@app.route('/collection/<int:collection_id>/album/<int:album_id>/edit',
           methods=['GET', 'POST'])
def editAlbum(collection_id, album_id):
    """ Edit an existing album in the database.

    Args:
        collection_id: An integer identifying a distinct collection.
        album_id: An integer identifying a distinct album.

    Returns:
        on GET: Page to edit an album.
        on POST: Redirect to collection page after album has been edited.
        Login page when user is not signed in.
        Alert when user is trying to edit an album he is not authorized to.

    Raises:
        OSError: An Error occured when deleting the former album cover image
            from the upload folder.

    Known Bugs:
        Uploaded album picture is deleted even when it is attached to another
        album as well.
    """
    if 'username' not in login_session:
        return redirect('/login')
    editedAlbum = session.query(Album).filter_by(id=album_id).one()
    collection = session.query(Collection).filter_by(id=collection_id).one()
    if login_session['user_id'] != collection.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to edit albums to this collection. Please create your own"
                " collection in order to edit albums.');}</script><body "
                "onload='myFunction()'>")
    if request.method == 'POST':
        if request.form['name']:
            editedAlbum.name = request.form['name']
        if request.form['artist']:
            editedAlbum.artist = request.form['artist']
        if request.form['genre']:
            editedAlbum.genre = request.form['genre']
        if request.form['year']:
            editedAlbum.year = request.form['year']
        if request.form['description']:
            editedAlbum.description = request.form['description']
        if request.form['image_source'] != 'no_change':
            if editedAlbum.cover_source == 'local':
                # Delete the old image from the server if it still exists.
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                              editedAlbum.cover_image))
                except OSError:
                    pass
            editedAlbum.cover_source, editedAlbum.cover_image = \
                process_image_source(request.form['image_source'])
        session.add(editedAlbum)
        session.commit()
        flash('Album Successfully Edited')
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('editAlbum.html',
                               collection_id=collection_id, album_id=album_id,
                               album=editedAlbum)


def process_image_source(image_source):
    """ Save image information to the database, depending on its source.

    Save image when local file is uploaded, save the path when url is
    given, otherwise just take the default image.

    This method is called from the editAlbum und deleteAlbum methods.

    Args:
        image_source: selected image_source in form.

    Returns:
        source: Local file, external url or no image.
        filename: Path or filename pointing to the image.

    """
    if image_source == 'local':
        source = 'local'
        # Access the image from the files dictionary on the request object.
        file = request.files['file']
        if file and allowed_file(file.filename):
            # Validate filename in case it is forged.
            filename = secure_filename(file.filename)
            # Save the image in the defined upload folder on the server.
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    elif image_source == 'url':
        source = 'url'
        filename = request.form['URL']
    else:
        source = None
        filename = 'no_cover.png'
    return (source, filename)


def allowed_file(filename):
    ''' Checks file for allowed extensions.

    Checks if file extension is in the predefined list of allowed extensions to
    make sure that users are not able to upload HTML files that would cause
    Cross-Site Scripting problems.
    '''

    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/collection/<int:collection_id>/album/<int:album_id>/delete',
           methods=['GET', 'POST'])
def deleteAlbum(collection_id, album_id):
    """ Delete an existing album in the database.

    Args:
        collection_id: An integer identifying a distinct collection.
        album_id: An integer identifying a distinct album.

    Returns:
        on GET: Page to delete an album.
        on POST: Redirect to collection page after album has been deleted.
        Login page when user is not signed in.
        Alert when user is trying to delete an album he is not authorized to.

    Raises:
        OSError: An Error occured when deleting the former album cover image
            from the upload folder.

    Known Bugs:
        Uploaded album picture is deleted even when it is attached to another
        album as well.
    """
    if 'username' not in login_session:
        return redirect('/login')
    collection = session.query(Collection).filter_by(id=collection_id).one()
    albumToDelete = session.query(Album).filter_by(id=album_id).one()
    if login_session['user_id'] != collection.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to delete albums to this collection. Please create your "
                "own collection in order to delete albums.');}</script><body "
                "onload='myFunction()'>")
    if request.method == 'POST':
        if albumToDelete.cover_source == 'local':
            # Delete the old image from the server if it still exists.
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'],
                          albumToDelete.cover_image))
            except OSError:
                pass
        session.delete(albumToDelete)
        session.commit()
        flash('Album Successfully Deleted')
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('deleteAlbum.html', album=albumToDelete,
                               collection=collection)


# User Helper Functions
def getUserID(email):
    """ Return a user ID from the database.

    Returns a user id for a given e-mail address if the e-mail address belongs
    to a user stored in the database.

    Args:
        email: e-mail address of a user.

    Returns:
        If successful, the user id to the given e-mail address, otherwise
            nothing.
    """

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    """ Returns the user object associated with the given id number.

    Args:
        user_id: An integer identifying a distinct user.

    Returns:
        A user object containing all fields of the found row in the database.

    Known Bugs:
        Experienced the follwoing error message when there is no entry in
        database afterclicking on a created collection:
        File "/vagrant/catalog/application.py", line 457, in indexAlbums
            creator = getUserInfo(collection.user_id)
        File "/vagrant/catalog/application.py", line 568, in getUserInfo
            user = session.query(User).filter_by(id=user_id).one()
        File "/usr/lib/python2.7/dist-packages/sqlalchemy/orm/query.py", line 2316, in one
            raise orm_exc.NoResultFound("No row was found for one()")
        NoResultFound: No row was found for one()
    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    """ Creates a new user in the database.

    Args:
        login_session: session object with user data.

    Returns:
        user.id: generated distinct integer value identifying the newly created
            user.

    Known Bugs:
        Experienced error message after first Login with Google:
        File "/vagrant/oauth/project.py", line 196, in gconnect
            user_id = createUser(login_session)
          File "/vagrant/oauth/project.py", line 581, in createUser
            user = session.query(User).filter_by(email=login_session['email']
                .one())
        AttributeError: 'unicode' object has no attribute 'one'
    """

    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'].one())
    return user.id


# The application run by the Python interpreter gets a name variable set to
# __main__, whereas all the other imported Python files get a __name__ variable
# set to the name of the actual Python file.
# The if-statement makes sure the server only runs if the script is executed
# directly from the Python interpreter and not used as an imported module.
if __name__ == '__main__':
    # Flash uses the secret key to create sessions for the users.
    app.secret_key = 'super_secret_key'
    # If debug is enabled, the server will reload itself each time it notices a
    # code change.
    app.debug = True
    # host='0.0.0.0' tells the webserver on the vagrant machine to listen on
    # all public IP-addresses.
    app.run(host='0.0.0.0', port=5000)
