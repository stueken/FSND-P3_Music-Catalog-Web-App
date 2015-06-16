# Item Catalog: Music Collection Web Application

A web application based on the [Flask][1] framework that provides a list of music albums within different collections. Thereby integrating third party user registration and authentication. Authenticated users have the ability to create, edit, and delete their own collections and albums.

![](http://image-store.slidesharecdn.com/d8542d9f-21c9-4db3-987d-b9d6b673d2b0-large.jpeg)

**Note:** This is a solution to project 3 of the [Udacity Full Stack Web Developer Nanodegree][2] based on the courses [Full Stack Foundations (ud088)][3] and [Authentication & Authorization: OAuth (ud330)][4]. The solution is graded with "Exceeds Specifications".

## Detailed Description

In addition to the basic functionality listed above, the following has been implemented:
- API Endpoints: A list of all collections, a distinct collection or album can also be accessed via [JSON][5] and [Atom][6] endpoints. Those can be reached when clicked on the shown hyperlinks throughout the web application.
- [CRUD][7] with album images: A cover image can be added for each album. This can be done either by uploading a local file or by providing an external image-url. If no image is added, a default image is shown. The album images are shown in the collection lists and can be edited and deleted as well.
- Prevent [CSRF][8]: Additionally to the already implemented state tokens for the third party sign-ins to prevent cross-site request forgery attacks, CSRF tokens have been added to all POST-forms using the Flask [SeaSurf][9] extension.
- Comments: All files are commented thoroughly and concise. As basis for styling the comments inside the Python files the [PEP-8][10] and [Google Style Guide][11] have been used.

## Important Files

There are multiple files in the `/` (base), `/templates` and `/static` folders. I will explain some of them in the following:

- **`application.py`**: This file contains the whole server side programming logic of the application.
- `database_setup.py': Contains the database model and is used to create the initial database.
- **`musiccollections.db`**: Database file containing some example collections to get started. If you run the `database_setup.py` file, this file gets replaced with an empty database.
- **`fb_client_secrets.json`** and **`g_client_secrtets.json`**: authorization information for Facebook and Google+ authentication. These can be used to try out the authorization options. However, for serious use, you should aquire your own keys.

## Requirements

The project has been run from a vagrant virtual machine, but basically the main requirements are the following:

- [Python 2.7][13]
- [SQLite][14]
- [SQLAlchemy][15]
- [Flask][16]
- [Flask extension SeaSurf][9]
- Python libraries: [httplib2][17], [oauth2client][18] and [Requests][19]

## Running Instructions

1. Change to the `/` (base) directory.
2. Start the local server by typing in `$ python application.py`.
3. Open a web browser and type in the URL `http://localhost:5000`.
4. Enjoy :)

## Planned Enhancements

1. Implement form validation.
2. Change to a many-to-many relationship between album and collection to make it possible to add existing albums to a collection.
3. Add Amazon sign-in as authorization option.

[1]: https://de.wikipedia.org/wiki/Flask "Wikipedia entry to Flask"
[2]: https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004 "Udacity Nanodegree: Full Stack Web Developer"
[3]: https://www.udacity.com/course/full-stack-foundations--ud088-nd "Udacity Course: Full Stack Foundations"
[4]: https://www.udacity.com/course/authentication-authorization-oauth--ud330-nd "Udacity Course: Authentication & Authorization: OAuth"
[5]: https://de.wikipedia.org/wiki/JavaScript_Object_Notation "Wikipedia entry: JavaScript Object Notation"
[6]: https://de.wikipedia.org/wiki/Atom_(Format) "Wikipedia entry: Atom (Format)"
[7]: https://de.wikipedia.org/wiki/CRUD "Wikipedia entry: CRUD"
[8]: https://de.wikipedia.org/wiki/Cross-Site-Request-Forgery "Wikipedia entry: Cross-Site-Request-Forgery"
[9]: https://flask-seasurf.readthedocs.org "SeaSurf Website"
[10]: https://www.python.org/dev/peps/pep-0008/ "Style Guide for Python Code"
[11]: https://google-styleguide.googlecode.com/svn/trunk/pyguide.html "Google Python Style Guide"
[12]: https://en.wikipedia.org/wiki/Vagrant_(software) "Wikipedia entry of Vagrant"
[13]: https://www.python.org/downloads/ "Download Python"
[14]: https://www.sqlite.org/download.html "Download SQLite"
[15]: http://www.sqlalchemy.org/download.html "Download SQLAlchemy"
[16]: http://flask.pocoo.org/ "Flask Website"
[17]: https://github.com/jcgregorio/httplib2 "GitHub repository for httplib2"
[18]: https://github.com/google/oauth2client "GitHub repository for oauth2client"
[19]: http://docs.python-requests.org/ "Reqests Website"
