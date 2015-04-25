# Item Catalog: Music Collection Web Application

Project to develop a web application based on the Flask framework that provides a list of music albums within different collections. Thereby integrating third party user registration and authentication. Authenticated users have the ability to create, edit, and delete their own collections and albums.

# Detailed Description

In addition to the basic functionality listed above, the following has been implemented:
- API Endpoints: A list of all collections, a distinct collection or album can also be accessed via JSON and Atom endpoints. Those can be reached when clicked on the shown hyperlinks through the web application.
- CRUD with album images: For each album a cover image can be added. This can be done either by uploading a local file or by stating an external url for the image. If no image is added, a default image will be shown. The album images are shown in the single collection lists and can be edited and deleted as well.
- Prevent CSRF: Additional to the already implemented state tokens for the third party sign ins to prevent cross-site request forgery attacks, CSRF tokens have been added to all POST-forms using the Flask SeaSurf extension.
- Comments: All files are commented thoroughly and concise. As basis for styling the comments in inside the Python files, the PEP-8 (https://www.python.org/dev/peps/pep-0008/) and Google Style Guide (https://google-styleguide.googlecode.com/svn/trunk/pyguide.html) have been used.

# Important Files

There are multiple files in the base, templates and static folders. I will explain some of them in the following:

- application.py: This file contains the whole server side programming logic of the application
- database_setup.py: Contains the database model and is used to create the initial database.
- musiccollections.db: Example database file already containing some collections to get started. If you run the database_setup.py file, this file gets replaced with an empty database.
- fb_client_secrets.json and g_client_secrtets.json: authorization information for Facebook and Google+ authentication. These can be used for trying the authorization options. However, for serious use, you should aquire your own keys.

# Requirements

The project has been run from a vagrant virtual machine, but basically the main requirements are the following:

    Python 2.7
    SQLite
   	SQLAlchemy
    Flask
    Flask extension SeaSurf
    Python libraries: httplib2, oauth2client and Requests

# Running Instructions

1. Change to the base directory
2. Start the local server by typing 'python application.py'
3. Open a web browser and type in the URL 'http://localhost:5000'
4. Enjoy :)

# Planned Enhancements

1. Implement form validation.
2. Change to a many-to-many relationship between album and collection and make it possible to add existing albums to a collection.
3. Add Amazaon sign-in as authorization option.

