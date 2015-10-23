Tools for commenting about commits on Bugzilla
----------------------------------------------

Any commits which reference a Bugzilla number will be posted as comments
on the bug. Bugs are specified either as '(#123456)' on the first line or
as 'Resolves: rhbz#123456' on any line of the commit message. Only one
comment per branch per bug is posted in Bugzilla.

The platform
============

wsgi.py implements the webhook. It's designed in particular for use with
mod_wsgi, but there's a main block to facilitate use as a standalone
application and that will probably work ok.

The web hook must be running somewhere with a publicly-accessible URL.

Configuration
=============

This service uses several environment variables for its configuration.

* *GHBH_BUGZILLA_URL* - The XML-RPC url to Bugzilla
* *GHBH_BUGZILLA_USERNAME* -  Username to read and post comments
* *GHBH_BUGZILLA_PASSWORD* - Login password

Optional configuration:

* *GHBH_GITHUB_SECRET* -  **Recommended** If set, this is the secret used to
configure the webhook on github, and is used to verify that push events are sent
from GitHub.
* *GHBH_HTTP_PORT* - The HTTP port to listen on if running the webhook as a
standalone service.

On GitHub
=========

Go to the settings for the repository you want to connect to Bugzilla. Under
"Webhooks & Services," add a webhook. Put in the URL for the web service,
select "application/json" for the content type, set a secret if you're using
one.

Under the choices of events to receive, select "Just the push event".

Bugs
====

Yes, probably. Feel free to contact me about this thing via github or email.
Patches welcome!

Credits
=======

Lots of the initial code and documentation is taken from David Shea's
https://github.com/rhinstaller/github-email-hook/
