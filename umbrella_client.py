# -*- coding: utf-8 -*-

# Copyright (c) 2018 CoNWeT Lab., Universidad Politécnica de Madrid

# This file is part of BAE Umbrella service plugin.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import json
import requests
import urllib
from datetime import datetime
from urlparse import urljoin, urlparse

from django.core.exceptions import PermissionDenied

from wstore.asset_manager.resource_plugins.plugin_error import PluginError


class UmbrellaClient(object):

    def __init__(self, server, token, key):
        self._server = server
        self._token = token
        self._key = key

    def _make_request(self, path, method, **kwargs):
        url = urljoin(self._server, path)
        try:
            resp = method(url, **kwargs)
        except requests.ConnectionError:
            raise PermissionDenied('Invalid resource: API Umbrella server is not responding')

        if resp.status_code == 404:
            raise PluginError('The provided Umbrella resource does not exist')
        elif resp.status_code != 200:
            raise PluginError('Umbrella gives an error accessing the provided resource')

        return resp

    def _get_request(self, path):
        resp = self._make_request(path, requests.get, headers={
            'X-Api-Key': self._key,
            'X-Admin-Auth-Token': self._token
        }, verify=False)

        return resp.json()

    def _put_request(self, path, body):
        self._make_request(path, requests.get, json=body, headers={
            'X-Api-Key': self._key,
            'X-Admin-Auth-Token': self._token
        }, verify=False)

    def _paginate_data(self, url, err_msg, page_processor)
        page_len = 100
        start = 0
        processed = False

        while not processed:
            result = self._get_request(url + '&start={}&length={}'.format(start, page_len))

            # There is no remaining elements
            if not len(result['data']):
                raise PluginError(err_msg)
            
            for elem in result['data']:
                processed = page_processor(elem)

                # The page element has been found
                if processed:
                    break
            
            start += page_len

    def validate_service(self, path):
        err_msg = 'The provided asset is not supported. ' \
                  'Only services protected by API Umbrella are supported'

        # Split the path of the service 
        paths = [p for p in path.split('/') if p != '']
        if not len(paths):
            # API umbrella resources include a path for matching the service
            raise PluginError(err_msg)

        # Make paginated requests to API umbrella looking for the provided paths
        url = '/api-umbrella/v1/apis.json?search[value]={}&search[regex]=false'.format(paths[0])
        def page_processor(api):
            front_path = [p for p in api['frontend_prefixes'].split('/') if p != '']
            return len(front_path) <= len(paths) and front_path == paths[:len(front_path)]

        self._paginate_data(url, err_msg, page_processor)

    def check_role(self, role):
        # Check that the provided role already exists, in order to avoid users creating new roles
        # using this service
        existing_roles = self._get_request('api-umbrella/v1/user_roles')
        for existing_role in existing_roles['user_roles']:
            if existing_role['id'] == role:
                break
        else:
            raise PluginError('The role {} does not exist in API Umbrella instance'.format(role))

    def _get_user_model(self, email):
        # Search users using the email field
        url = '/api-umbrella/v1/users?search[value]={}'.format(email)
        err_msg = 'There is not any user registered in Umbrella instance with email: {}'.format(email)

        user_id = None
        def page_processor(user):
            processed = False
            if user_result['email'] == email:
                user_id = user_result['id']
                processed = True
            
            return processed

        self._paginate_data(url, err_msg, page_processor)

        # Get user model
        return self._get_request('/api-umbrella/v1/users/{}'.format(user_id))

    def _filter_roles(self, user_model, role):
        new_roles = []
        if user_model['user']['roles'] is not None:
            # Parse existing roles
            new_roles = [user_role for user_role in user_model['user']['roles'] if user_role != role]

        return new_roles

    def grant_permission(self, user, role):
        self.check_role(role)
        user_model = self._get_user_model(user.email)

        # Update user roles
        new_roles = self._filter_roles(user_model, role).append(role)

        user_model['user']['roles'] = new_roles

        self._put_request('/api-umbrella/v1/users/{}'.format(user_model['user']['id']), user_model)

    def revoke_permission(self, user, role):
        self.check_role(role)
        user_model = self._get_user_model(user.email)
        user_model['user']['roles'] = self._filter_roles(user_model, role)
        self._put_request('/api-umbrella/v1/users/{}'.format(user_model['user']['id']), user_model)

    def _get_rule(self, field, value):
        return {
            'id': field,
            'field': field,
            'type': 'string',
            'input': 'text',
            'operator': 'equal',
            'value': value
        }

    def get_drilldown_by_service(self, email, service, start_at, end_at):
        parsed_url = urlparse(service)
        rules = [
            self._get_rule('user_email', email), self._get_rule('request_path', parsed_url.path)]

        if len(parsed_url.query):
            rules.append(self._get_rule('request_url_query', parsed_url.query))

        query = {
            'condition': 'AND',
            'rules': rules,
            'valid': True
        }

        query_param = urllib.quote(json.dumps(query), safe='')
        prefix = '2/{}/{}/'.format(parsed_url.netloc, parsed_url.path.split('/')[1])

        query_string = '?start_at={}&end_at={}&interval=day&query={}&prefix={}&beta_analytics=false'.format(
            start_at, end_at, query_param, prefix
        )
        stats = self._get_request('/api-umbrella/v1/analytics/drilldown.json' + query_string)['hits_over_time']

        accounting = []
        for daily_stat in stats['rows']:
            if len(daily_stat['c']) > 1 and daily_stat['c'][1]['v'] > 0:
                date = datetime.strptime(daily_stat['c'][0]['f'], '%a, %b %d, %Y')
                accounting.append({
                    'unit': 'api call',
                    'value': daily_stat['c'][1]['f'],
                    'date': unicode(date.isoformat()).replace(' ', 'T') + 'Z'
                })

        return accounting
