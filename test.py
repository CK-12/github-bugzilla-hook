#!/usr/bin/python3.4

import json
import wsgi
import unittest

class FakeBugzilla(object):
    comments = {
        'bugs': {
            '999999': {
                'comments': [{
                    'count': 0,
                    'author': 'atodorov@redhat.com',
                    'text': 'Description of problem:',
                    'creator': 'atodorov@redhat.com',
                    'bug_id': 999999,
                    'creator_id': 210279,
                    'id': 8749185,
                    'is_private': False
                }, {
                    'count': 1,
                    'author': 'atodorov@redhat.com',
                    'text': """
https://github.com/atodorov/bztest/commit/8ee2da3e225008f17bc89439f72bd6652111942a
Branch: master
Author: Alexander Todorov <atodorov@redhat.com>
Date:   2015-10-23 13:19:13+03:00

    2nd commit (#123456)
    
    Resolves: rhbz#999999
""",
                    'creator': 'atodorov@redhat.com',
                    'bug_id': 999999,
                    'creator_id': 210279,
                    'id': 8749241,
                    'is_private': True
                }]
            },

            '123456': {
                'comments': [{
                    'count': 0,
                    'author': 'atodorov@redhat.com',
                    'text': 'Description of problem:',
                    'creator': 'atodorov@redhat.com',
                    'bug_id': 123456,
                    'creator_id': 210279,
                    'id': 8749185,
                    'is_private': False
                }]
            },
        },
        'comments': {}
    }

    def get_comments(self, bug_id):
        return self.comments

    def update_bugs(self, bug_id, update):
        pass


class TestGHBH_TestCase(unittest.TestCase):
    data = """
{
    "ref":"refs/heads/master",
    "commits":[
        {
            "id":"d3faddfaddb9eac64f00a09df73cbb783c6ad855",
            "distinct":true,
            "message":"First commit (#123456)",
            "timestamp":"2015-10-23T13:18:47+03:00",
            "url":"https://github.com/atodorov/bztest/commit/d3faddfaddb9eac64f00a09df73cbb783c6ad855",
            "author":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                },
            "committer":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                },
            "added":[],
            "removed":[],
            "modified":["README"]
        },
        {
            "id":"8ee2da3e225008f17bc89439f72bd6652111942a",
            "distinct":true,
            "message":"2nd commit (#123456)\\n\\nResolves: rhbz#999999",
            "timestamp":"2015-10-23T13:19:13+03:00",
            "url":"https://github.com/atodorov/bztest/commit/8ee2da3e225008f17bc89439f72bd6652111942a",
            "author":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                },
            "committer":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                },
            "added":[],
            "removed":[],
            "modified":["README"]
        }
    ]
}
"""

    data = json.loads(data)

    def test_get_bugs(self):
        bugs = wsgi.get_bugs(self.data)
        bzs = bugs.keys()
        self.assertEqual(len(bzs), 2)
        self.assertTrue('123456' in bzs)
        self.assertTrue('999999' in bzs)

        # assert number of commits per bug is as expected
        self.assertEqual(len(bugs['123456']), 2)
        self.assertEqual(len(bugs['999999']), 1)

    def test_get_comments(self):
        comments = wsgi.get_comments(self.data)
        bzs = comments.keys()
        self.assertEqual(len(bzs), 2)
        self.assertTrue('123456' in bzs)
        self.assertTrue('999999' in bzs)

        comment_1 = comments['123456']
        # bug 123456 is referenced in two commits
        self.assertTrue(comment_1.find("d3faddfaddb9eac64f00a09df73cbb783c6ad855") > -1)
        self.assertTrue(comment_1.find("8ee2da3e225008f17bc89439f72bd6652111942a") > -1)

        comment_2 = comments['999999']
        # bug 999999 is referenced only in the second commit
        self.assertEqual(comment_2.find("d3faddfaddb9eac64f00a09df73cbb783c6ad855"), -1)
        self.assertTrue(comment_2.find("8ee2da3e225008f17bc89439f72bd6652111942a") > -1)


    def test_post_to_bugzilla(self):
        """
            - Bug 999999 already has a comment on it so don't post a new one,
            - Bug 123456 doesn't have any comments from us so update it
        """
        posts = wsgi.post_to_bugzilla(FakeBugzilla(), self.data)

        # comment posted only for bug 123456
        self.assertEqual(posts, 1)

    def test_post_to_bugzilla_2_branches_same_bug(self):
        """
            If a commit on another branch references the same bug we
            have to add a comment for it. Bug 999999 already has a comment
            for the master branch.
        """
        data = """
{
    "ref":"refs/heads/new_branch",
    "commits":[
        {
            "id":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "url":"https://github.com/atodorov/bztest/commit/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "message":"Commit on another branch\\n\\nResolves: rhbz#999999",
            "timestamp":"2015-10-23T13:18:47+03:00",
            "author":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                }
        }
    ]
}
"""
        data = json.loads(data)
        posts = wsgi.post_to_bugzilla(FakeBugzilla(), data)
        self.assertEqual(posts, 1)

    def test_post_to_bugzilla_same_branch_separate_commits(self):
        """
            If separate commits (pushed later) on the branch reference
            the same bug we are not going to add a comment for it.
            Bug 999999 already has a comment for the master branch.
        """
        data = """
{
    "ref":"refs/heads/master",
    "commits":[
        {
            "id":"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "url":"https://github.com/atodorov/bztest/commit/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "message":"Commit on another branch\\n\\nResolves: rhbz#999999",
            "timestamp":"2015-10-23T13:18:47+03:00",
            "author":
                {
                    "name":"Alexander Todorov",
                    "email":"atodorov@redhat.com",
                    "username":"atodorov"
                }
        }
    ]
}
"""
        data = json.loads(data)
        posts = wsgi.post_to_bugzilla(FakeBugzilla(), data)
        self.assertEqual(posts, 0)

if __name__ == '__main__':
    unittest.main()
