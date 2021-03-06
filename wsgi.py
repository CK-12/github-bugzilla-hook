#!/usr/bin/env python
#
# GitHub to Bugzilla bridge
#
# Copyright (C) 2015
# Red Hat, Inc.  All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Author(s): David Shea <dshea@redhat.com>
# Author(s): Alexander Todorov <atodorov@redhat.com>
#

# For use with mod_wsgi, though it could probably be run ok with the wsgiref
# httpd.

from __future__ import print_function

import os
import sys
import re
import json
import hmac
import hashlib
import bugzilla

HOME_DIR = '/var/www/github-bugzilla-hook'

sys.path.insert(0, HOME_DIR)
from settings import setEnv
setEnv()

FORCE_COMMENT = True


def application(environ, start_response):
    """ Entry point for mod_wsgi """

    # We always respond with text/plain no matter what, so set that
    response_headers = [('Content-Type', 'text/plain')]

    # Check that all the necessary environment variables are set
    if 'GHBH_BUGZILLA_URL' not in os.environ or \
        'GHBH_BUGZILLA_USERNAME' not in os.environ or \
        'GHBH_BUGZILLA_PASSWORD' not in os.environ:
        print("Missing required environment variables", file=environ['wsgi.errors'])
        return http_error(start_response, '500 Internal Server Error', 'Service not properly configured, please check that all mandatory environment variables are set')

    # Check that this request is the right kind of thing: a POST of type
    # application/json with a known length
    if environ['REQUEST_METHOD'] != 'POST':
        return http_error(start_response, '405 Method Not Allowed', 'Only POST messages are accepted')

    if 'CONTENT_TYPE' not in environ or environ['CONTENT_TYPE'] != 'application/json':
        print("Invalid content-type %s" % environ.get('CONTENT_TYPE', None),
                file=environ['wsgi.errors'])
        return http_error(start_response, '415 Unsupported Media Type', 'Requests must be of type application/json')

    try:
        content_length = int(environ['CONTENT_LENGTH'])
    except (KeyError, ValueError):
        return http_error(start_response, '411 Length required', 'Invalid content length')

    # Look for the github headers
    if 'HTTP_X_GITHUB_EVENT' not in environ:
        print("Missing X-Github-Event", file=environ['wsgi.errors'])
        return http_error(start_response, '400 Bad Request', 'Invalid event type')

    event_type = environ['HTTP_X_GITHUB_EVENT']
    print("event_type: %s" % event_type)

    # Read the post data
    # Errors will be automatically converted to a 500
    post_data = environ['wsgi.input'].read(content_length)
    #print("post_data: %s" % post_data)

    # If a secret was set, validate the post data
    if 'GHBH_GITHUB_SECRET' in os.environ:
        if 'HTTP_X_HUB_SIGNATURE' not in environ:
            print("Missing signature", file=environ['wsgi.errors'])
            return http_error(start_response, '401 Unauthorized', 'Invalid signature')

        # Only sha1 is used currently
        if not environ['HTTP_X_HUB_SIGNATURE'].startswith('sha1='):
            print("Signature not sha1", file=environ['wsgi.errors'])
            return http_error(start_response, '401 Unauthorized', 'Invalid signature')

        digester = hmac.new(os.environ['GHBH_GITHUB_SECRET'].encode('utf-8'),
                msg=post_data, digestmod=hashlib.sha1)
        if 'sha1=' + digester.hexdigest() != environ['HTTP_X_HUB_SIGNATURE']:
            print("Signature mismatch", file=environ['wsgi.errors'])
            return http_error(start_response, '401 Unauthorized', 'Invalid signature')


    global HOME_DIR
    home_dir = HOME_DIR
    if not home_dir:
        home_dir = os.environ.get('OPENSHIFT_DATA_DIR', os.environ.get('HOME', ''))
    cookie_file = os.path.join(home_dir, '.bugzillacookies')
    token_file = os.path.join(home_dir, '.bugzillatoken')
    bz = bugzilla.Bugzilla(
                        url=os.environ['GHBH_BUGZILLA_URL'],
                        cookiefile=cookie_file,
                        tokenfile=token_file
                    )
    try:
        bz.login(os.environ['GHBH_BUGZILLA_USERNAME'], os.environ['GHBH_BUGZILLA_PASSWORD'])
    except bugzilla.BugzillaError as e:
        print("Bugzilla error: %s" % e.message , file=environ['wsgi.errors'])
        return http_error(start_response, '500 Internal Server Error', 'Bugzilla error: %s' % e.message)

    # Convert the post data to a string so we can start actually using it
    # JSON is required to be in utf-8, utf-16, or utf-32, but github only ever
    # uses utf-8, praise be, so just go ahead and assume that
    try:
        post_str = post_data.decode('utf-8')
    except UnicodeDecodeError:
        print("Unable to decode JSON", file=environ['wsgi.errors'])
        start_response('400 Bad Request', response_headers)
        return http_error(start_response, '400 Bad Request', 'Invalid data')

    # Parse the post data
    try:
        if 'bug' not in post_str.lower():
            return skip_processing(start_response, 'No bug string found. Skipping.')
        event_data = json.loads(post_str)
    except ValueError:
        print("Unable to parse JSON", file=environ['wsgi.errors'])
        return http_error(start_response, '400 Bad Request', 'Invalid data')

    # Done with parsing the request, dispatch the data to the event handler
    if event_type in ["push", "pull_request"]:
        if event_type == 'pull_request':
            ## Get action
            pr_action = event_data.get('action')
            if not pr_action or pr_action.lower() not in [ 'opened', 'merged', 'closed']:
                print("Skipping pr_action[%s]" % (pr_action))
                return skip_processing(start_response, 'Skipping unsupported PR action [%s].' % pr_action)

        post_to_bugzilla(bz, event_data, event_type)

    start_response('200 OK', response_headers)
    return [b'']

def safe_decode(s):
    return s.decode('utf-8') if s and type(s).__name__ == 'str' else s

def safe_encode(s):
    return s.encode('utf-8') if s and type(s).__name__ == 'unicode' else s

def http_error(start_response, codeStr, msg):
    response_headers = [('Content-Type', 'text/plain')]
    start_response(codeStr, response_headers)
    return [safe_encode(msg + '\n')]

def skip_processing(start_response, msg):
    response_headers = [('Content-Type', 'text/plain')]
    start_response('200 OK', response_headers)
    print("skip_processing: [%s]" % msg)
    return [safe_encode(msg + '\n')]

def get_bugs(data):
    """
        https://developer.github.com/v3/activity/events/types/#pushevent
    """

    supported_cmds = {'fixed':      'Fixed',
                      'fixes':      'Fixed',
                      'addresses':  'Refers',
                      're':         'Refers',
                      'references': 'Refers',
                      'refs':       'Refers',
                      'refer':      'Refers',
                      'refers':     'Refers',
                      'reopens':    'Reopens',
                      'reopen':     'Reopens'}

    bugs = {}

    #build re to look for reference to a bug
    bug_prefix = '(?:#|(?:Bug|Bug:|bug|bug:|BUG|BUG:)[: ]?)'
    bug_reference = bug_prefix + '[0-9]+'
    bug_command =  (r'(?P<action>[A-Za-z]*).?'
                       '(?P<ticket>%s(?:(?:[, &]*|[ ]?and[ ]?)%s)*)' %
                       (bug_reference, bug_reference))
    command_re = re.compile(bug_command)
    bug_re = re.compile(bug_prefix + '([0-9]+)')

    #find all references to bugzilla bugs

    if not 'commits' in data and data.get('pull_request'):
        data['commits'] = [
		{
		    'id': '',
		    'distinct': True,
		    'message': data['pull_request'].get('title', '') + '\n' + data['pull_request']['body'],
		    'url': data['pull_request']['html_url'] + '/files',
		    'author': { 'name': data['pull_request']['user']['login'], 'email': '' },
		    'timestamp': data['pull_request']['created_at'],
		},
	    ]

    for commit in data["commits"]:
        sha = commit["id"]
        if not commit.get('distinct', False):
            print("Skipping the commit because it is not distinct: %s" % sha)
            continue
        message = commit["message"]
        summary = message.split("\n")[0].strip()
        body = message.split("\n")[1:]
        msg = summary + " ".join(body)
        ## Causes UnicodeEncode error
        #print("commit msg: [%s]" % msg)
	cmd_groups = command_re.findall(msg)

        for command, bugstrs in cmd_groups:
            print("Processing command[%s], bugs[%s]" % (command, bugstrs))
            if command == 'request':
                continue
            bug = bug_re.findall(bugstrs)[0]
            action = supported_cmds.get(command.lower(),'')
            if bug not in bugs:
                bugs[bug] = [(commit, action)]
            else:
                bugs[bug].append((commit, action))

        print("bugs after body: [%s]" % str(bugs))

    return bugs

def get_comments(data, event_type):
    """
        https://developer.github.com/v3/activity/events/types/#pushevent
    """
    def indent(lines):
        padding = "    "
        return padding + ('\n'+padding).join(lines.split('\n'))

    bugs = get_bugs(data)
    branch, pr_url, pr_action = '', '', ''
    if 'ref' in data:
        branch = data["ref"].replace("refs/heads/", "")
    elif 'pull_request' in data:
        pr_url = data['pull_request'].get('html_url')
        pr_state = data.get('action')
    comments = {}

    #print(bugs)
    for bug in bugs.keys():
        for commit, action in bugs[bug]:
            author = commit['author']['name']
            if commit['author']['email']:
                author += ' <' + commit['author']['email'] + '>'
            brinfo = ''
            if branch:
                brinfo = 'Branch:        %s' % branch
            elif pr_url:
                action = ''
                brinfo = 'Pull Request:  %s [%s]' % (pr_url, pr_state)
            comment = """
Patch:         %s
%s
Author:        %s
Date:          %s

%s
""" % (commit["url"], brinfo, author, commit["timestamp"].replace("T", " "), indent(commit["message"]))
            if not bug in comments:
                #comments[bug] = {'comment': comment, 'action': action, 'changedIn': changedIn, 'id': commit['id'], 'branch': branch}
                comments[bug] = {'comment': comment, 'action': action, 'id': commit['id'], 'branch': branch, 'pr_url': pr_url }
            else:
                comments[bug]['comment'] += comment

    #print("comments: [%s]" % comments)
    return comments

def post_to_bugzilla(bz, data, event_type):
    """
        Return the number of posted bugs for testing purposes
    """
    comments = get_comments(data, event_type)
    posts = 0

    for bug_id in comments.keys():
        text = comments[bug_id]['comment'].strip()
        action = comments[bug_id]['action']
        #changedIn = comments[bug_id]['changedIn']
        revid = comments[bug_id]['id']
        branchName = comments[bug_id]['branch']
        has_comment = False

        # search by commits for particular branches
        branchre = re.search("Branch: (.+)\n", text)
        if branchre:
            branch = branchre.group()
        else:
            branch = None

        comment_list = bz.get_comments(bug_id)
        comment_list = comment_list['bugs'][bug_id]['comments']

        for bug_comment in comment_list:
            comment_text = bug_comment['text'].strip()
            if branch and comment_text.find(branch) > -1:
                has_comment = True
                print("Found the comment for id: %s. Skipping? [%s]" % (revid, not FORCE_COMMENT))
                break

        ## Get existing branches in bug
        bugObj = bz.getbug(bug_id)
        existingBranches = bugObj.cf_commit_branch
        if existingBranches:
            existingBranches = [ x.strip() for x in existingBranches.split(',')]
        else:
            existingBranches = []
        if branchName and branchName not in existingBranches:
            existingBranches.append(branchName)

        if not has_comment or FORCE_COMMENT:
            updateParams = bz.build_update(comment=text) #, keywords_add=changedIn)
            updateParams['cf_fixversion'] = revid
            updateParams['cf_commit_branch'] = ', '.join(existingBranches)
            if action == 'Fixed':
                updateParams['status'] = 'RESOLVED'
                updateParams['resolution'] = 'FIXED'
            elif action == 'Reopens':
                updateParams['status'] = 'REOPENED'
            else:
                print("No action found in the commit message.")
            print("Update params: %s" % updateParams)
            bz.update_bugs(bug_id, updateParams)
            posts += 1

    return posts


# Service, serve thyself
# This is only needed for running outside of mod_wsgi
if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    try:
        httpd = make_server('', os.environ.get('GHBH_HTTP_PORT', 8080), application)
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Exiting on user interrupt")
