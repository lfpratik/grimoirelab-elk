# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2020 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Alvaro del Castillo San Felix <acs@bitergia.com>
#   Quan Zhou <quan@bitergia.com>
#

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys

import requests

from urllib.parse import urlparse

from grimoire_elk.errors import ElasticError
from grimoire_elk.elastic import ElasticSearch
# Connectors for Graal
from graal.backends.core.coqua import CoQua, CoQuaCommand
from graal.backends.core.cocom import CoCom, CoComCommand
from graal.backends.core.codep import CoDep, CoDepCommand
from graal.backends.core.colic import CoLic, CoLicCommand
# Connectors for Perceval
from grimoire_elk.raw.hyperkitty import HyperKittyOcean
from perceval.backends.core.askbot import Askbot, AskbotCommand
from perceval.backends.core.bugzilla import Bugzilla, BugzillaCommand
from perceval.backends.core.bugzillarest import BugzillaREST, BugzillaRESTCommand
from perceval.backends.core.confluence import Confluence, ConfluenceCommand
from perceval.backends.core.discourse import Discourse, DiscourseCommand
from perceval.backends.core.dockerhub import DockerHub, DockerHubCommand
from perceval.backends.finos.finosmeetings import FinosMeetings, FinosMeetingsCommand
from perceval.backends.core.gerrit import Gerrit, GerritCommand
from perceval.backends.core.git import Git, GitCommand
from perceval.backends.core.github import GitHub, GitHubCommand
from perceval.backends.core.githubql import GitHubQL, GitHubQLCommand
from perceval.backends.core.gitlab import GitLab, GitLabCommand
from perceval.backends.core.gitter import Gitter, GitterCommand
from perceval.backends.core.googlehits import GoogleHits, GoogleHitsCommand
from perceval.backends.core.groupsio import Groupsio, GroupsioCommand
from perceval.backends.core.hyperkitty import HyperKitty, HyperKittyCommand
from perceval.backends.core.jenkins import Jenkins, JenkinsCommand
from perceval.backends.core.jira import Jira, JiraCommand
from perceval.backends.core.launchpad import Launchpad, LaunchpadCommand
from perceval.backends.core.mattermost import Mattermost, MattermostCommand
from perceval.backends.core.mbox import MBox, MBoxCommand
from perceval.backends.core.mediawiki import MediaWiki, MediaWikiCommand
from perceval.backends.core.meetup import Meetup, MeetupCommand
from perceval.backends.core.nntp import NNTP, NNTPCommand
from perceval.backends.core.pagure import Pagure, PagureCommand
from perceval.backends.core.phabricator import Phabricator, PhabricatorCommand
from perceval.backends.core.pipermail import Pipermail, PipermailCommand
from perceval.backends.core.twitter import Twitter, TwitterCommand
from perceval.backends.puppet.puppetforge import PuppetForge, PuppetForgeCommand
from perceval.backends.core.redmine import Redmine, RedmineCommand
from perceval.backends.core.rocketchat import RocketChat, RocketChatCommand
from perceval.backends.core.rss import RSS, RSSCommand
from perceval.backends.core.slack import Slack, SlackCommand
from perceval.backends.core.stackexchange import StackExchange, StackExchangeCommand
from perceval.backends.core.supybot import Supybot, SupybotCommand
from perceval.backends.core.telegram import Telegram, TelegramCommand
from perceval.backends.mozilla.crates import Crates, CratesCommand
from perceval.backends.mozilla.kitsune import Kitsune, KitsuneCommand
from perceval.backends.mozilla.mozillaclub import MozillaClub, MozillaClubCommand
from perceval.backends.mozilla.remo import ReMo, ReMoCommand
from perceval.backends.opnfv.functest import Functest, FunctestCommand
from perceval.backends.weblate.weblate import Weblate, WeblateCommand

# Connectors for EnrichOcean
from .enriched.askbot import AskbotEnrich
from .enriched.bugzilla import BugzillaEnrich
from .enriched.bugzillarest import BugzillaRESTEnrich
from .enriched.cocom import CocomEnrich
from .enriched.colic import ColicEnrich
from .enriched.dockerdeps import Dockerdeps
from .enriched.dockersmells import Dockersmells
from .enriched.confluence import ConfluenceEnrich
from .enriched.crates import CratesEnrich
from .enriched.discourse import DiscourseEnrich
from .enriched.dockerhub import DockerHubEnrich
from .enriched.finosmeetings import FinosMeetingsEnrich
from .enriched.functest import FunctestEnrich
from .enriched.gerrit import GerritEnrich
from .enriched.git import GitEnrich
from .enriched.github import GitHubEnrich
from .enriched.githubql import GitHubQLEnrich
from .enriched.github2 import GitHubEnrich2
from .enriched.gitlab import GitLabEnrich
from .enriched.gitter import GitterEnrich
from .enriched.google_hits import GoogleHitsEnrich
from .enriched.groupsio import GroupsioEnrich
from .enriched.hyperkitty import HyperKittyEnrich
from .enriched.jenkins import JenkinsEnrich
from .enriched.jira import JiraEnrich
from .enriched.kitsune import KitsuneEnrich
from .enriched.launchpad import LaunchpadEnrich
from .enriched.mattermost import MattermostEnrich
from .enriched.mbox import MBoxEnrich
from .enriched.mediawiki import MediaWikiEnrich
from .enriched.meetup import MeetupEnrich
from .enriched.mozillaclub import MozillaClubEnrich
from .enriched.nntp import NNTPEnrich
from .enriched.pagure import PagureEnrich
from .enriched.phabricator import PhabricatorEnrich
from .enriched.pipermail import PipermailEnrich
from .enriched.puppetforge import PuppetForgeEnrich
from .enriched.redmine import RedmineEnrich
from .enriched.remo import ReMoEnrich
from .enriched.rocketchat import RocketChatEnrich
from .enriched.rss import RSSEnrich
from .enriched.slack import SlackEnrich
from .enriched.stackexchange import StackExchangeEnrich
from .enriched.supybot import SupybotEnrich
from .enriched.telegram import TelegramEnrich
from .enriched.twitter import TwitterEnrich
from .enriched.weblate import WeblateEnrich
# Connectors for Ocean
from .raw.askbot import AskbotOcean
from .raw.bugzilla import BugzillaOcean
from .raw.bugzillarest import BugzillaRESTOcean
from .raw.confluence import ConfluenceOcean
from .raw.crates import CratesOcean
from .raw.discourse import DiscourseOcean
from .raw.dockerhub import DockerHubOcean
from .raw.elastic import ElasticOcean
from .raw.finosmeetings import FinosMeetingsOcean
from .raw.functest import FunctestOcean
from .raw.gerrit import GerritOcean
from .raw.git import GitOcean
from .raw.github import GitHubOcean
from .raw.githubql import GitHubQLOcean
from .raw.gitlab import GitLabOcean
from .raw.gitter import GitterOcean
from .raw.google_hits import GoogleHitsOcean
from .raw.graal import GraalOcean
from .raw.groupsio import GroupsioOcean
from .raw.jenkins import JenkinsOcean
from .raw.jira import JiraOcean
from .raw.kitsune import KitsuneOcean
from .raw.launchpad import LaunchpadOcean
from .raw.mattermost import MattermostOcean
from .raw.mbox import MBoxOcean
from .raw.mediawiki import MediaWikiOcean
from .raw.meetup import MeetupOcean
from .raw.mozillaclub import MozillaClubOcean
from .raw.nntp import NNTPOcean
from .raw.pagure import PagureOcean
from .raw.phabricator import PhabricatorOcean
from .raw.pipermail import PipermailOcean
from .raw.puppetforge import PuppetForgeOcean
from .raw.redmine import RedmineOcean
from .raw.remo import ReMoOcean
from .raw.rocketchat import RocketChatOcean
from .raw.rss import RSSOcean
from .raw.slack import SlackOcean
from .raw.stackexchange import StackExchangeOcean
from .raw.supybot import SupybotOcean
from .raw.telegram import TelegramOcean
from .raw.twitter import TwitterOcean
from .raw.weblate import WeblateOcean

logger = logging.getLogger(__name__)

kibiter_version = None


def get_connector_from_name(name):

    # Remove extra data from data source section: remo:activities
    name = name.split(":")[0]
    found = None
    connectors = get_connectors()

    for cname in connectors:
        if cname == name:
            found = connectors[cname]

    return found


def get_connector_name(cls):
    found = None
    connectors = get_connectors()

    for cname in connectors:
        for con in connectors[cname]:
            if cls == con:
                if found:
                    # The canonical name is included in the classname
                    if cname in cls.__name__.lower():
                        found = cname
                else:
                    found = cname
    return found


def get_connector_name_from_cls_name(cls_name):
    found = None
    connectors = get_connectors()

    for cname in connectors:
        for con in connectors[cname]:
            if not con:
                continue
            if cls_name == con.__name__:
                if found:
                    # The canonical name is included in the classname
                    if cname in con.__name__.lower():
                        found = cname
                else:
                    found = cname
    return found


def get_connectors():

    return {"askbot": [Askbot, AskbotOcean, AskbotEnrich, AskbotCommand],
            "bugzilla": [Bugzilla, BugzillaOcean, BugzillaEnrich, BugzillaCommand],
            "bugzillarest": [BugzillaREST, BugzillaRESTOcean, BugzillaRESTEnrich, BugzillaRESTCommand],
            "cocom": [CoCom, GraalOcean, CocomEnrich, CoComCommand],
            "colic": [CoLic, GraalOcean, ColicEnrich, CoLicCommand],
            "dockerdeps": [CoDep, GraalOcean, Dockerdeps, CoDepCommand],
            "dockersmells": [CoQua, GraalOcean, Dockersmells, CoQuaCommand],
            "confluence": [Confluence, ConfluenceOcean, ConfluenceEnrich, ConfluenceCommand],
            "crates": [Crates, CratesOcean, CratesEnrich, CratesCommand],
            "discourse": [Discourse, DiscourseOcean, DiscourseEnrich, DiscourseCommand],
            "dockerhub": [DockerHub, DockerHubOcean, DockerHubEnrich, DockerHubCommand],
            "finosmeetings": [FinosMeetings, FinosMeetingsOcean, FinosMeetingsEnrich, FinosMeetingsCommand],
            "functest": [Functest, FunctestOcean, FunctestEnrich, FunctestCommand],
            "gerrit": [Gerrit, GerritOcean, GerritEnrich, GerritCommand],
            "git": [Git, GitOcean, GitEnrich, GitCommand],
            "github": [GitHub, GitHubOcean, GitHubEnrich, GitHubCommand],
            "githubql": [GitHubQL, GitHubQLOcean, GitHubQLEnrich, GitHubQLCommand],
            "github2": [GitHub, GitHubOcean, GitHubEnrich2, GitHubCommand],
            "gitlab": [GitLab, GitLabOcean, GitLabEnrich, GitLabCommand],
            "gitter": [Gitter, GitterOcean, GitterEnrich, GitterCommand],
            "google_hits": [GoogleHits, GoogleHitsOcean, GoogleHitsEnrich, GoogleHitsCommand],
            "groupsio": [Groupsio, GroupsioOcean, GroupsioEnrich, GroupsioCommand],
            "hyperkitty": [HyperKitty, HyperKittyOcean, HyperKittyEnrich, HyperKittyCommand],
            "jenkins": [Jenkins, JenkinsOcean, JenkinsEnrich, JenkinsCommand],
            "jira": [Jira, JiraOcean, JiraEnrich, JiraCommand],
            "kitsune": [Kitsune, KitsuneOcean, KitsuneEnrich, KitsuneCommand],
            "launchpad": [Launchpad, LaunchpadOcean, LaunchpadEnrich, LaunchpadCommand],
            "mattermost": [Mattermost, MattermostOcean, MattermostEnrich, MattermostCommand],
            "mbox": [MBox, MBoxOcean, MBoxEnrich, MBoxCommand],
            "mediawiki": [MediaWiki, MediaWikiOcean, MediaWikiEnrich, MediaWikiCommand],
            "meetup": [Meetup, MeetupOcean, MeetupEnrich, MeetupCommand],
            "mozillaclub": [MozillaClub, MozillaClubOcean, MozillaClubEnrich, MozillaClubCommand],
            "nntp": [NNTP, NNTPOcean, NNTPEnrich, NNTPCommand],
            "pagure": [Pagure, PagureOcean, PagureEnrich, PagureCommand],
            "phabricator": [Phabricator, PhabricatorOcean, PhabricatorEnrich, PhabricatorCommand],
            "pipermail": [Pipermail, PipermailOcean, PipermailEnrich, PipermailCommand],
            "puppetforge": [PuppetForge, PuppetForgeOcean, PuppetForgeEnrich, PuppetForgeCommand],
            "redmine": [Redmine, RedmineOcean, RedmineEnrich, RedmineCommand],
            "remo": [ReMo, ReMoOcean, ReMoEnrich, ReMoCommand],
            "rocketchat": [RocketChat, RocketChatOcean, RocketChatEnrich, RocketChatCommand],
            "rss": [RSS, RSSOcean, RSSEnrich, RSSCommand],
            "slack": [Slack, SlackOcean, SlackEnrich, SlackCommand],
            "stackexchange": [StackExchange, StackExchangeOcean,
                              StackExchangeEnrich, StackExchangeCommand],
            "supybot": [Supybot, SupybotOcean, SupybotEnrich, SupybotCommand],
            "telegram": [Telegram, TelegramOcean, TelegramEnrich, TelegramCommand],
            "twitter": [Twitter, TwitterOcean, TwitterEnrich, TwitterCommand],
            "weblate": [Weblate, WeblateOcean, WeblateEnrich, WeblateCommand]
            }  # Will come from Registry


def get_elastic(url, es_index, clean=None, backend=None, es_aliases=None, mapping=None):

    analyzers = None

    if backend:
        backend.set_elastic_url(url)
#        mapping = backend.get_elastic_mappings()
        mapping = backend.mapping
        analyzers = backend.get_elastic_analyzers()
    try:
        insecure = True
        elastic = ElasticSearch(url=url, index=es_index, mappings=mapping,
                                clean=clean, insecure=insecure,
                                analyzers=analyzers, aliases=es_aliases)

    except ElasticError:
        msg = "Can't connect to Elastic Search. Is it running?"
        logger.error(msg)
        sys.exit(1)

    return elastic


def get_kibiter_version(url):
    """
        Return kibiter major number version

        The url must point to the Elasticsearch used by Kibiter
    """

    config_url = '.kibana/config/_search'
    # Avoid having // in the URL because ES will fail
    if url[-1] != '/':
        url += "/"
    url += config_url
    r = requests.get(url)
    r.raise_for_status()

    if len(r.json()['hits']['hits']) == 0:
        logger.error("Can not get the Kibiter version")
        return None

    version = r.json()['hits']['hits'][0]['_id']
    # 5.4.0-SNAPSHOT
    major_version = version.split(".", 1)[0]
    return major_version


def config_logging(debug):

    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')
        logging.debug("Debug mode activated")
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    # Per commit log is too verbose
    logging.getLogger("perceval.backends.core.git").setLevel(logging.WARNING)


USAGE_MSG = ''
DESC_MSG = ''
EPILOG_MSG = ''


def get_params_parser():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(usage=USAGE_MSG,
                                     description=DESC_MSG,
                                     epilog=EPILOG_MSG,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     add_help=False)

    ElasticOcean.add_params(parser)

    parser.add_argument('-h', '--help', action='help',
                        help=argparse.SUPPRESS)
    parser.add_argument('-g', '--debug', dest='debug',
                        action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument("--no_incremental", action='store_true',
                        help="don't use last state for data source")
    parser.add_argument("--fetch_cache", action='store_true',
                        help="Use cache for item retrieval")
    parser.add_argument("--enrich", action='store_true',
                        help="Enrich items after retrieving")
    parser.add_argument("--enrich_only", action='store_true',
                        help="Only enrich items (DEPRECATED, use --only-enrich)")
    parser.add_argument("--only-enrich", dest='enrich_only', action='store_true',
                        help="Only enrich items")
    parser.add_argument("--filter-raw", dest='filter_raw',
                        help="Filter raw items. Format: field:value")
    parser.add_argument("--events-enrich", dest='events_enrich', action='store_true',
                        help="Enrich events in items")
    parser.add_argument('--index', help="Ocean index name")
    parser.add_argument('--index-enrich', dest="index_enrich", help="Ocean enriched index name")
    parser.add_argument('--db-user', help="User for db connection (default to root)",
                        default="root")
    parser.add_argument('--db-password', help="Password for db connection (default empty)",
                        default="")
    parser.add_argument('--db-host', help="Host for db connection (default to mariadb)",
                        default="mariadb")
    parser.add_argument('--db-projects-map', help="Projects Mapping DB")
    parser.add_argument('--json-projects-map', help="Projects Mapping JSON file")
    parser.add_argument('--project', help="Project for the repository (origin)")
    parser.add_argument('--refresh-projects', action='store_true', help="Refresh projects in enriched items")
    parser.add_argument('--db-sortinghat', help="SortingHat DB")
    parser.add_argument('--only-identities', action='store_true', help="Only add identities to SortingHat DB")
    parser.add_argument('--refresh-identities', action='store_true', help="Refresh identities in enriched items")
    parser.add_argument('--author_id', nargs='*', help="Field author_ids to be refreshed")
    parser.add_argument('--author_uuid', nargs='*', help="Field author_uuids to be refreshed")
    parser.add_argument('--github-token', help="If provided, github usernames will be retrieved in git enrich.")
    parser.add_argument('--jenkins-rename-file', help="CSV mapping file with nodes renamed schema.")
    parser.add_argument('--studies', action='store_true', help="Execute studies after enrichment.")
    parser.add_argument('--only-studies', action='store_true', help="Execute only studies.")
    parser.add_argument('--bulk-size', default=1000, type=int,
                        help="Number of items per bulk request to Elasticsearch.")
    parser.add_argument('--scroll-wait', default=900, type=int, help="Wait for available scroll (default 900s)")
    parser.add_argument('--scroll-size', default=100, type=int,
                        help="Number of items to get from Elasticsearch when scrolling.")
    parser.add_argument('--pair-programming', action='store_true', help="Do pair programming in git enrich")
    parser.add_argument('--studies-list', nargs='*', help="List of studies to be executed")
    parser.add_argument('backend', help=argparse.SUPPRESS)
    parser.add_argument('backend_args', nargs=argparse.REMAINDER,
                        help=argparse.SUPPRESS)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser


def get_params():
    """ Get params definition from ElasticOcean and from all the backends """

    parser = get_params_parser()
    args = parser.parse_args()

    if not args.enrich_only and not args.only_identities and not args.only_studies:
        if not args.index:
            # Check that the raw index name is defined
            print("[error] --index <name> param is required when collecting items from raw")
            sys.exit(1)

    return args


class GitOps:

    def __init__(self, url):
        self.base_path = '~/.perceval/repositories'
        self.git_url = self.__get_processed_uri(url)
        self.uptodate = False
        self.follow_hierarchy = False
        self._cache = {}

    def __del__(self):
        pass

    @property
    def cache_path(self):
        path = os.path.expanduser('~/.perceval/cache')
        if not os.path.exists(path):
            os.makedirs(path)
        return '~/.perceval/cache'

    @property
    def cache_file_name(self):
        return 'stats.json'

    @property
    def repo_path(self):
        return self.__get_git_repo_path()

    @property
    def org_name(self):
        parser = urlparse(self.git_url)
        org_name = self._build_org_name(parser.netloc)
        if self.is_gitsource(parser.netloc):
            org_name = self._build_org_name(parser.path)
        return org_name

    @property
    def repo_name(self):
        parser = urlparse(self.git_url)
        return self._build_repo_name(parser.path, self.org_name)

    def _build_repo_name(self, path, org_name):
        sanitize_path = self.sanitize_url(path)
        if org_name in sanitize_path:
            sanitize_path = sanitize_path.replace('{0}/'.format(self.org_name), '')
        if not self.follow_hierarchy:
            return sanitize_path.replace('/', '-').replace('_', '-')
        return sanitize_path

    def _build_org_name(self, path):
        sanitize_path = self.sanitize_url(path)
        if '.' in sanitize_path:
            return sanitize_path.split('.')[1]
        return sanitize_path.split('/')[0]

    @staticmethod
    def __get_processed_uri(uri):
        return uri.lstrip('/').replace('.git', '')

    def __get_base_path(self):
        return os.path.expanduser(self.base_path)

    def __get_cache_path(self):
        base_path = os.path.expanduser(self.cache_path)
        path = os.path.join(base_path, self.org_name)
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    def __get_git_repo_path(self):
        base_path = self.__get_base_path()
        if self.follow_hierarchy:
            return os.path.join(base_path, '{0}/{1}'.format(self.org_name, self.repo_name))
        return os.path.join(base_path, '{0}-{1}'.format(self.org_name, self.repo_name))

    @staticmethod
    def is_gitsource(host):
        if 'github.com' in host \
                or 'gitlab.com' in host \
                or 'bitbucket.org' in host:
            return True
        return False

    @staticmethod
    def sanitize_url(path):
        if path.startswith('/r/'):
            path = path.replace('/r/', '')
        elif path.startswith('/gerrit/'):
            path = path.replace('/gerrit/', '')
        path = path.lstrip('/')
        return path

    @staticmethod
    def sanitize_os_output(result):
        """
        Sanitize the os command output and return the readable output
        """
        sanitized_output = result.decode('UTF-8')

        return sanitized_output

    @staticmethod
    def _exec(cmd, cwd=None, env=None, ignored_error_codes=None,
              encoding='utf-8'):
        """Run a command.

        Execute `cmd` command in the directory set by `cwd`. Environment
        variables can be set using the `env` dictionary. The output
        data is returned as encoded bytes.

        Commands which their returning status codes are non-zero will
        be treated as failed. Error codes considered as valid can be
        ignored giving them in the `ignored_error_codes` list.

        :returns: the output of the command as encoded bytes

        :raises RepositoryError: when an error occurs running the command
        """
        if ignored_error_codes is None:
            ignored_error_codes = []

        logger.debug("Running command %s (cwd: %s, env: %s)",
                     ' '.join(cmd), cwd, str(env))

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    cwd=cwd, env=env)
            (outs, errs) = proc.communicate()
        except OSError as e:
            raise RepositoryError(cause=str(e))

        if proc.returncode != 0 and proc.returncode not in ignored_error_codes:
            err = errs.decode(encoding, errors='surrogateescape')
            cause = "git command - %s" % err
            raise RepositoryError(cause=cause)
        else:
            logger.debug(errs.decode(encoding, errors='surrogateescape'))

        return outs

    def _stats(self, path):
        if path and os.path.exists(path):
            cmd = ['cloc', path]
            env = {
                'LANG': 'C',
                'HOME': os.getenv('HOME', '')
            }
            return self._exec(cmd, env=env)

        return ''.encode('utf-8')

    def _pls(self, result):
        """
            Get the programing language summary
        """
        def extract_program_language_summary(value):
            stats = list()
            lan_smry_lst = value.split('\n')
            if 'SUM:' in value and len(lan_smry_lst) > 0:
                for smry in lan_smry_lst[::-1]:
                    if smry.startswith('---') or len(smry) == 0:
                        continue
                    elif smry.startswith('Language'):
                        break
                    else:
                        smry_result = smry.split()
                        stats.append({
                            'language': smry_result[0].replace('SUM:', 'Total'),
                            'files': smry_result[1],
                            'blank': smry_result[2],
                            'comment': smry_result[3],
                            'code': smry_result[4]
                        })

            return stats

        return extract_program_language_summary(self.sanitize_os_output(result))

    def _loc(self, result):
        """
        Get the total lines of code from the default branch
        """
        def extract_lines_of_code(value):
            if len(value) > 0 and 'SUM:' in value:
                return int((value.split('\n')[-3]).split(' ')[-1])
            return 0

        return extract_lines_of_code(self.sanitize_os_output(result))

    def _clone(self):
        """Clone a Git repository.

        Make a bare copy of the repository stored in `uri` into `dirpath`.
        The repository would be either local or remote.

        :param uri: URI of the repository
        :param dirtpath: directory where the repository will be cloned

        :returns: a `GitRepository` class having cloned the repository

        :raises RepositoryError: when an error occurs cloning the given
            repository
        """
        cmd = ['git', 'clone', self.git_url, self.repo_path]
        env = {
            'LANG': 'C',
            'HOME': os.getenv('HOME', '')
        }

        try:
            self._exec(cmd, env=env)
            logger.debug("Git %s repository cloned into %s",
                         self.git_url, self.repo_path)
        except (RuntimeError, Exception) as cloe:
            logger.error("Git clone error %s ", str(cloe))

    def _clean(self):
        cmd = ['rm', '-rf', self.repo_path]
        env = {
            'LANG': 'C',
            'HOME': os.getenv('HOME', '')
        }

        try:
            self._exec(cmd, env=env)
            logger.debug("Git %s repository clean", self.repo_path)
        except (RuntimeError, Exception) as cle:
            logger.error("Git clone error %s", str(cle))

    def _pull(self):
        os.chdir(os.path.abspath(self.repo_path))
        env = {
            'LANG': 'C',
            'HOME': os.getenv('HOME', '')
        }
        branch = None
        status = False

        try:
            cmd_auto = ['git', 'remote', 'set-head', 'origin', '--auto']
            cmd_short = ['git', 'symbolic-ref', '--short', 'refs/remotes/origin/HEAD']
            self._exec(cmd_auto, env=env)
            result = self._exec(cmd_short, env=env)
            result = self.sanitize_os_output(result)
            branch = result.replace('origin/', '').strip()
            logger.debug("Git %s repository active branch is: %s",
                         self.repo_path, branch)
        except (RuntimeError, Exception) as be:
            logger.error("Git find active branch error %s", str(be))

        try:
            if branch:
                cmd = ['git', 'checkout', branch]
                self._exec(cmd, env=env)
                logger.debug("Git %s repository "
                             "checkout with following branch %s",
                             self.repo_path, branch)
        except (RuntimeError, Exception) as gce:
            logger.error("Git checkout error %s", str(gce))

        try:
            if branch:
                cmd = ['git', 'pull', 'origin', branch]
                result = self._exec(cmd, env=env)
                result = self.sanitize_os_output(result)
                if len(result) >= 18:
                    status = True
                logger.debug("Git %s repository pull updated code",
                             self.repo_path)
            else:
                logger.debug("Git repository active branch missing")
                logger.debug("Git %s repository pull request skip ",
                             self.repo_path)
        except (RuntimeError, Exception) as pe:
            logger.error("Git pull error %s", str(pe))

        return status

    def _fetch(self):
        os.chdir(os.path.abspath(self.repo_path))

        cmd_fetch = ['git', 'fetch']
        cmd_fetch_p = ['git', 'fetch']

        env = {
            'LANG': 'C',
            'HOME': os.getenv('HOME', '')
        }

        try:
            self._exec(cmd_fetch, env=env)
            logger.debug("Git %s fetch updated code", self.repo_path)
        except (RuntimeError, Exception) as fe:
            logger.error("Git fetch purge error %s", str(fe))

        try:
            self._exec(cmd_fetch_p, env=env)
            logger.debug("Git %s fetch purge code", self.repo_path)
        except (RuntimeError, Exception) as fpe:
            logger.error("Git fetch purge error %s", str(fpe))

    def _build_empty_stats_data(self):
        stats_data = {
            self.repo_name: {
                'loc': 0,
                'pls': [],
                'timestamp': None
            }
        }
        return stats_data

    def _write_json_file(self, data, path, filename):
        try:
            path = os.path.join(path, filename)
            with open(path, 'w') as f:
                f.write(json.dumps(data, indent=4))
            f.close()
        except Exception as je:
            logger.error("cache file write error %s", str(je))
        finally:
            pass

    def _read_json_file(self, path, filename):
        error = None
        try:
            path = os.path.join(path, filename)
            with open(path, 'r') as f:
                data = f.read()
            f.close()
            return json.loads(data)
        except Exception as je:
            logger.error("cache file write error %s", str(je))
            error = True
        finally:
            if error:
                return self._build_empty_stats_data()

    def _load_cache(self):
        path = os.path.join(self.__get_cache_path(), self.cache_file_name)

        if not os.path.exists(path):
            stats_data = self._build_empty_stats_data()
            self._cache = stats_data
            self._write_json_file(data=stats_data,
                                  path=self.__get_cache_path(),
                                  filename=self.cache_file_name)
        else:
            self._cache = self._read_json_file(path=self.__get_cache_path(),
                                               filename=self.cache_file_name)

            if self.repo_name not in self._cache.keys():
                self._cache.update(self._build_empty_stats_data())
                self._write_json_file(data=self._cache,
                                      path=self.__get_cache_path(),
                                      filename=self.cache_file_name)

    def _get_cache_item(self, project_name, key):
        return self._cache[project_name][key]

    def _update_cache_item(self, project_name, key, value):
        data = self._cache.get(project_name)
        data[key] = value
        self._cache.update({project_name: data})

    def _delete_cache_item(self, project_name, key=None):
        if key:
            del self._cache[project_name][key]
        del self._cache[project_name]

    def load(self):
        if self.repo_path and not os.path.exists(self.repo_path):
            self._clone()
        else:
            self._fetch()
            self.uptodate = self._pull()

    def get_stats(self):
        loc = self._get_cache_item(self.repo_name, 'loc')
        pls = self._get_cache_item(self.repo_name, 'pls')

        if not self.uptodate or (loc == 0 and len(pls) == 0):
            result = self._stats(self.repo_path)
            loc = self._loc(result)
            pls = self._pls(result)
            self._update_cache_item(project_name=self.repo_name,
                                    key='loc',
                                    value=loc)
            self._update_cache_item(project_name=self.repo_name,
                                    key='pls',
                                    value=pls)
            utc_date = datetime.datetime.utcnow()
            if utc_date.tzinfo is None:
                utc_date = utc_date.replace(tzinfo=datetime.timezone.utc)
            self._update_cache_item(project_name=self.repo_name,
                                    key='timestamp',
                                    value=utc_date.isoformat())
            self._write_json_file(data=self._cache,
                                  path=self.__get_cache_path(),
                                  filename=self.cache_file_name)

        return loc, pls
