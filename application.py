from flask import (Flask, render_template, request, redirect, jsonify, url_for,
                   flash)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Collection, Album, User

# To prevent anti-forgery request attacks a unique session token needs to be
# created that the client side returns alaongside the Google generated
# authorization code.
# The login_session object works like a dictionary. We can store values in it
# for the longevity of a user session with our server
from flask import session as login_session
import random
import string

# The flow_from_clientsecrets method creates a flow object from the
# clientsecrets-JSON-file. This JSON-formatted file stores your client id,
# client secret and other OAuth2 parameters
from oauth2client.client import flow_from_clientsecrets
# The FlowExchangeError method is used if we run into an error trying to
# exchange an authorization code for an access token. We can use this
# FlowExchangeError method to catch it.
from oauth2client.client import FlowExchangeError
# httplib2 is a comprehensive http client library in python
import httplib2
# The json module provides an api converting inmemory python objects to a
# serialized representation known as json or javascript object notation.
import json
# The make_response method converts the return value from a function into a
# real response object that we can send off to our client.
from flask import make_response
# requests is an apache2 license http-library written in python similar to
# urllib2, but with a few improvements
import requests

# Create an instance of the Flask class with the name of the running
# application as the argument. Anytime an application in python is run, a
# special variable called __name__ gets defined for the application and all the
# imports it uses.
app = Flask(__name__)

# Declare client_id by referencing the client_secrets file
CLIENT_ID = json.loads(
    open('g_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Music Collection Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///musiccollections.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login')
def showLogin():
    ''' Create a random anti-forgery state token with each GET request sent to
    localhost:5000/login before rendering the login page.
    '''

    # Create a variable which will be 32 characters long and a mix of uppercase
    # letters and digits.
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    # Store state in the login_session object under the name 'state'
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Server side function to handle the state-token and the one-time-code
    send from the client callback function.
    '''
    # Confirm that the token the client sends to the server matches the
    # token that the server sends to the client. This roundship verification
    # helps ensure that the user is making the request and and not a malicious
    # script.
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
        # the one-time code as input. The step2_exchange-function of the flow-
        # class exchanges an authorization (one-time) code for an credentials
        # object.
        # If all goes well, the response from Google will be an object which
        # is stored under the name credentials.
        credentials = oauth_flow.step2_exchange(code)
    # If an error happens along the way, then I will throw this
    # FlowExchangeError and send the response as an json-object.
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
    # Create a json get-request containing the url and access-token and store
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
    # login_session['credentials'] = credentials
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Use the google plus API to get some more information about the user.
    # Here, a message is send off to the google API server with my access token
    # requesting the user info allowed by my token scope and store it in an
    # object called data.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    # Data should all of the values listed on
    # https://developers.google.com/+/api/openidconnect/getOpenIdConnect#response
    # filled in, so long as the user specified them in their account. In the
    # following, the users name, picture and e-mail address are stored it in my
    # login session.
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]

    # see if user exists, if it doesn't make a new one
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


# Disconnect - Revoke a current user's token and reset their login_session.
@app.route("/gdisconnect")
def gdisconnect():
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


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Similarily to the Google login, the value of state is verified to protect
    # against cross-site reference forgery attacks.
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
    userinfo_url = "https://graph.facebook.com/v2.2/me"
    # The long-lived token includes an expires-field that indicates how long
    # this token is valid. Longterm tokens can last up to two months.
    # Strip expire tag from access token since it is not needed to make API
    # calls.
    token = result.split("&")[0]

    # If the token works API calls should be possible like in the
    # following.
    url = 'https://graph.facebook.com/v2.2/me?%s' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    # populate the login session
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

    # see if user exists, if it doesn't make a new one
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


@app.route("/fbdisconnect")
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # Execute HTTP GET request to revoke current token.
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "You have been logged out."


# JSON APIs to view Collection Information
@app.route('/collection/<int:collection_id>/album/JSON')
def collectionJSON(collection_id):
    collection = session.query(Collection).filter_by(id=collection_id).one()
    albums = session.query(Album).filter_by(
        collection_id=collection_id).all()
    return jsonify(Albums=[a.serialize for a in albums])


@app.route('/collection/<int:collection_id>/album/<int:album_id>/JSON')
def AlbumJSON(collection_id, album_id):
    album = session.query(Album).filter_by(id=album_id).one()
    return jsonify(album=album.serialize)


@app.route('/collection/JSON')
def collectionsJSON():
    collections = session.query(Collection).all()
    return jsonify(Collections=[c.serialize for c in collections])


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            # del login_session['credentials']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
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


# The decorator '@' actually wraps the following function inside the
# app.route-function that flask has already created. So if either of these
# routes get sent from the browser the following function gets executed.
# decorators in python can be stacked one on top of the other, so
# @app.rout('/') will call the @app.rout('/hello'), which will call the
# HelloWorld-function. This is useful for having different urls all route to
# the same place.

# Show all collections
@app.route('/')
@app.route('/collection/')
def indexCollections():
    collections = session.query(Collection).order_by(asc(Collection.name))
    if 'username' not in login_session:
        return render_template('publicCollections.html',
                               collections=collections)
    else:
        return render_template('indexCollections.html',
                               collections=collections)


# Create a new collection
@app.route('/collection/new/', methods=['GET', 'POST'])
def newCollection():
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


# Edit a collection
@app.route('/collection/<int:collection_id>/edit/', methods=['GET', 'POST'])
def editCollection(collection_id):
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


# Delete a collection
@app.route('/collection/<int:collection_id>/delete/', methods=['GET', 'POST'])
def deleteCollection(collection_id):
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


# Show albums
@app.route('/collection/<int:collection_id>/')
@app.route('/collection/<int:collection_id>/album/')
def indexAlbums(collection_id):
    collection = session.query(Collection).filter_by(id=collection_id).one()
    creator = getUserInfo(collection.user_id)
    albums = session.query(Album).filter_by(
        collection_id=collection_id).all()
    if ('username' not in login_session or
            creator.id != login_session['user_id']):
        return render_template('publicCollection.html', albums=albums,
                               collection=collection, creator=creator)
    # The logged in user is the creator of the collection.
    else:
        return render_template('indexAlbums.html', albums=albums,
                               collection=collection,
                               creator=creator)


# Create a new album
@app.route('/collection/<int:collection_id>/album/new/',
           methods=['GET', 'POST'])
def newAlbum(collection_id):
    if 'username' not in login_session:
        return redirect('/login')
    collection = session.query(Collection).filter_by(id=collection_id).one()
    if login_session['user_id'] != collection.user_id:
        return ("<script>function myFunction() {alert('You are not authorized "
                "to add albums to this collection. Please create your own "
                "collection in order to add albums.');}</script><body "
                "onload='myFunction()'>")
    if request.method == 'POST':
        newAlbum = Album(name=request.form['name'],
                         artist=request.form['artist'],
                         genre=request.form['genre'],
                         year=request.form['year'],
                         description=request.form['description'],
                         collection_id=collection_id,
                         user_id=login_session['user_id'])
        session.add(newAlbum)
        session.commit()
        flash('New album %s album Successfully Created' % (newAlbum.name))
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('newAlbum.html', collection_id=collection_id)


# Edit a album
@app.route('/collection/<int:collection_id>/album/<int:album_id>/edit',
           methods=['GET', 'POST'])
def editAlbum(collection_id, album_id):
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
            editedAlbum.price = request.form['year']
        if request.form['description']:
            editedAlbum.description = request.form['description']
        session.add(editedAlbum)
        session.commit()
        flash('Album Successfully Edited')
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('editAlbum.html',
                               collection_id=collection_id, album_id=album_id,
                               album=editedAlbum)


# Delete a album
@app.route('/collection/<int:collection_id>/album/<int:album_id>/delete',
           methods=['GET', 'POST'])
def deleteAlbum(collection_id, album_id):
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
        session.delete(albumToDelete)
        session.commit()
        flash('Album Successfully Deleted')
        return redirect(url_for('indexAlbums', collection_id=collection_id))
    else:
        return render_template('deleteAlbum.html', album=albumToDelete,
                               collection=collection)


# User Helper Functions
def getUserID(email):
    ''' Returns an e-mail address for a given user id if the id belongs to a
    user stored in the database. '''

    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    ''' Returns the user object associated with the given id number. '''

    '''
    !!!
    Error when no entry in database after clicking on a created collection:
    File "/vagrant/catalog/application.py", line 457, in indexAlbums
        creator = getUserInfo(collection.user_id)
    File "/vagrant/catalog/application.py", line 568, in getUserInfo
        user = session.query(User).filter_by(id=user_id).one()
    File "/usr/lib/python2.7/dist-packages/sqlalchemy/orm/query.py", line 2316, in one
        raise orm_exc.NoResultFound("No row was found for one()")
    NoResultFound: No row was found for one()
    !!!
    '''
    user = session.query(User).filter_by(id=user_id).one()
    print user
    return user


def createUser(login_session):
    ''' Creates a new user in the database. '''

    '''
    !!!
    Error after first Login with Google:
    File "/vagrant/oauth/project.py", line 196, in gconnect
        user_id = createUser(login_session)
      File "/vagrant/oauth/project.py", line 581, in createUser
        user = session.query(User).filter_by(email=login_session['email']
            .one())
    AttributeError: 'unicode' object has no attribute 'one'
    !!!
    '''

    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email'].one())
    return user.id


# The application run by the python interpreter gets a name variable set to
# __main__, whereas all the other imported python files get a __name__ variable
# set to the name of the actual python file.
# The if-statement makes sure the server only runs if the script is executed
# directly from the python interpreter and not used as an imported module.
if __name__ == '__main__':
    # flash uses the secret key to create sessions for the users
    app.secret_key = 'super_secret_key'
    # If debug is enabled, the server will reload itself each time it notices a
    # code change
    app.debug = True
    # host='0.0.0.0' tells the webserver on the vagrant machine to listen on
    # all public IP-addresses
    app.run(host='0.0.0.0', port=5000)
