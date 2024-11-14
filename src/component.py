'''
Template Component main class.
'''

import csv
import logging
import requests
import pandas as pd
from datetime import datetime, timedelta

from keboola.component.base import ComponentBase
import keboola.component.exceptions


# Configuration variables
KEY_CLIENT_ID = '#client_id'
KEY_CLIENT_SECRET = '#client_secret'
KEY_USERNAME = 'username'
KEY_PASSWORD = '#password'
KEY_APP_ID = 'app_id'

# List of mandatory parameters
REQUIRED_PARAMETERS = [KEY_CLIENT_ID, KEY_CLIENT_SECRET, KEY_USERNAME, KEY_PASSWORD, KEY_APP_ID]
REQUIRED_IMAGE_PARS = []

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)   # Nastaví logování requests pouze na varování a chyby
logging.getLogger("urllib3").setLevel(logging.WARNING)     # Nastaví logování urllib3 pouze na varování a chyby




class Component(ComponentBase):
    """
    Extends base class for general Python components. Initializes the CommonInterface
    and performs configuration validation.
    """

    def __init__(self):
        super().__init__()
        self.access_token = None
        self.authenticate_podio()

    # Authenticate to Podio API and retrieve access token
    def authenticate_podio(self):
        params = self.configuration.parameters
        logging.info("Authenticating to Podio API")
        auth_url = 'https://podio.com/oauth/token'
        auth_data = {
            'grant_type': 'password',
            'client_id': params.get(KEY_CLIENT_ID),
            'client_secret': params.get(KEY_CLIENT_SECRET),
            'username': params.get(KEY_USERNAME),
            'password': params.get(KEY_PASSWORD),
        }

        response = requests.post(auth_url, data=auth_data)
        if response.status_code == 200:
            auth_json = response.json()
            logging.info("Successful authentication")
            self.access_token = auth_json['access_token']
        else:
            logging.error("Authentication error: " + response.text)
            raise Exception("Authentication failed: " + response.text)

    # Retrieve items from Podio with pagination
    def get_all_podio_items(self, app_id, max_items=1000, batch_size=500):
        offset = 0
        all_items = []

        while len(all_items) < max_items:
            batch_items = self.get_podio_items(app_id, limit=batch_size, offset=offset)
            all_items.extend(batch_items)
            if len(batch_items) < batch_size:
                # No more items to fetch
                break
            offset += batch_size

        return all_items[:max_items]

    # Retrieve items from Podio with limit and offset
    def get_podio_items(self, app_id, limit=500, offset=0):
        url = f'https://api.podio.com/item/app/{app_id}/'
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        params = {
            'limit': limit,
            'offset': offset
        }

        logging.info(f"Retrieving items from Podio, limit: {limit}, offset: {offset}")
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            logging.error(f"Error retrieving items: {response.text}")
            raise Exception(f"Failed to retrieve items: {response.text}")

        return response.json().get('items', [])

    # Transform Podio items into DataFrame
    def transform_podio_items(self, items):
        transformed_data = []
        for item in items:
            item_data = {
                'item_id': item['item_id'],
                'external_id': item.get('external_id', None),
                'request_number': item.get('app_item_id_formatted', None),
                'request_link': item.get('link', None),
                'title': item['title'],
                'created_on': item['created_on'],
                'last_event_on': item.get('last_event_on', None),
                'created_by_name': item['created_by']['name'] if 'created_by' in item else None,
                'realizuje_name': None,
                'stav_text': None,
                'datum_zmeny_stavu': None,
                'kontrola_splneni_text': None,
                'oblast_text': None,
                'priorita_text': None,
                'schvaleni_text': None,
                'prostredi_text': None,
                'signifikantni_zmena': None,
                'poznamky_text': None,
                'files': None,
                'tags': None,
                'tasks': None,
                'jira_project_text': None,
                'jira_link': None,
                'pozadavek_text': None,
                'zadani_text': None,
                'zainteresovane_osoby': None
            }

            # Retrieve custom fields (fields)
            for field in item['fields']:
                field_label = field['label']
                field_values = field['values']

                if field_label == 'Požadavek':
                    item_data['pozadavek_text'] = field_values[0]['value'] if field_values else None
                elif field_label == 'Stav':
                    item_data['stav_text'] = field_values[0]['value']['text'] if field_values else None
                    if item.get('last_event_on'):
                        item_data['datum_zmeny_stavu'] = item['last_event_on']
                elif field_label == 'Kontrola splnění požadavku':
                    item_data['kontrola_splneni_text'] = field_values[0]['value']['text'] if field_values else None
                elif field_label == 'Oblast':
                    item_data['oblast_text'] = field_values[0]['value']['text'] if field_values else None
                elif field_label == 'Klasifikace':
                    item_data['priorita_text'] = field_values[0]['value']['text'] if field_values else None
                elif field_label == 'Schválení':
                    item_data['schvaleni_text'] = field_values[0]['value']['text'] if field_values else None
                elif field_label == 'Prostředí':
                    # Prostředí může být vícenásobné, takže extrahujeme všechna prostředí jako text
                    item_data['prostredi_text'] = ', '.join([env['value']['text'] for env in field_values])
                elif field_label == 'Signifikantní změna':
                    item_data['signifikantni_zmena'] = field_values[0]['value']['text'] if field_values else None
                elif field_label == 'Poznámky':
                    item_data['poznamky_text'] = field_values[0]['value'] if field_values else None
                elif field_label == 'Realizuje':
                    item_data['realizuje_name'] = field_values[0]['value']['name'] if field_values else None
                elif field_label == 'Zainteresované osoby':
                    item_data['zainteresovane_osoby'] = ', '.join([person['value']['name'] for person in field_values])
                elif field_label == 'Jira Link':
                    item_data['jira_link'] = field_values[0]['value'] if field_values else None
                elif field_label == 'Zadání':
                    item_data['zadani_text'] = field_values[0]['value'] if field_values else None

            # Collect files, tags, and tasks if available
            if 'files' in item and item['files']:
                item_data['files'] = ', '.join([file['name'] for file in item['files']])
            if 'tags' in item and item['tags']:
                item_data['tags'] = ', '.join(item['tags'])
            if 'tasks' in item and item['tasks']:
                item_data['tasks'] = ', '.join([task['title'] for task in item['tasks']])

            transformed_data.append(item_data)

        # Convert to Pandas DataFrame
        df = pd.DataFrame(transformed_data)
        logging.info(f"Data transformation completed, records: {len(df)}")
        return df

    def get_revision_differences(self, item_id, revision_from, revision_to, headers):
        diff_url = f'https://api.podio.com/item/{item_id}/revision/{revision_from}/{revision_to}'
        diff_response = requests.get(diff_url, headers=headers)
        if diff_response.status_code == 200:
            differences = diff_response.json()

            extracted_diffs = []
            for diff in differences:
                if diff.get("type") != "category":
                    continue

                field_id = diff.get("field_id")
                external_id = diff.get("external_id")
                label = diff.get("label")

                from_value = [item["value"].get("text", "N/A") for item in diff.get("from", [{"value": {"text": "N/A"}}])]
                to_value = [item["value"].get("text", "N/A") for item in diff.get("to", [{"value": {"text": "N/A"}}])]

                extracted_diffs.append({
                    "field_id": field_id,
                    "external_id": external_id,
                    "label": label,
                    "previous_value": ", ".join(from_value),
                    "new_value": ", ".join(to_value)
                })
            return extracted_diffs
        else:
            logging.error(f"Error retrieving revision differences: {diff_response.text}")
            return None

    def get_item_revisions_and_comments(self, item, access_token):
        item_id = item['item_id']
        request_number = item.get('app_item_id_formatted', None)
        headers = {'Authorization': f'Bearer {access_token}'}
        activities = []
        date_threshold = datetime.now() - timedelta(days=10)

        # Získání revizí
        revision_url = f'https://api.podio.com/item/{item_id}/revision'
        revision_response = requests.get(revision_url, headers=headers)
        if revision_response.status_code == 200:
            revisions = [
                rev for rev in revision_response.json()
                if datetime.strptime(rev['created_on'], '%Y-%m-%d %H:%M:%S') >= date_threshold
            ]

            # Přidání první revize (creation)
            if revisions:
                creation_revision = revisions[0]
                activities.append({
                    'ID': item_id,
                    'request_number': request_number,
                    'type': 'creation',
                    'author': creation_revision.get('created_by', {}).get('name', 'Unknown'),
                    'date': creation_revision.get('created_on'),
                    'changed_field': 'initial creation',
                    'previous_value': None,
                    'new_value': 'Item created'
                })

            # Zpracování dalších revizí
            for i in range(1, len(revisions)):
                prev_revision = revisions[i - 1]
                current_revision = revisions[i]

                revision_diff = self.get_revision_differences(
                    item_id,
                    prev_revision['revision'],
                    current_revision['revision'],
                    headers
                )
                if revision_diff:
                    for change in revision_diff:
                        activities.append({
                            'ID': item_id,
                            'request_number': request_number,
                            'type': 'update',
                            'author': current_revision.get('created_by', {}).get('name', 'Unknown'),
                            'date': current_revision.get('created_on'),
                            'changed_field': change['label'],
                            'previous_value': change['previous_value'],
                            'new_value': change['new_value']
                        })

        else:
            logging.error(f"Error retrieving revisions for item {item_id}: {revision_response.text}")

        # Získání komentářů
        comment_url = f'https://api.podio.com/comment/item/{item_id}'
        comment_response = requests.get(comment_url, headers=headers)
        if comment_response.status_code == 200:
            comments = [
                comment for comment in comment_response.json()
                if datetime.strptime(comment['created_on'], '%Y-%m-%d %H:%M:%S') >= date_threshold
            ]
            for comment in comments:
                activities.append({
                    'ID': item_id,
                    'request_number': request_number,
                    'type': 'comment',
                    'author': comment.get('created_by', {}).get('name', 'Unknown'),
                    'date': comment.get('created_on'),
                    'changed_field': 'comment',
                    'new_value': comment.get('value')
                })
        else:
            logging.error(f"Error retrieving comments for item {item_id}: {comment_response.text}")

        return activities

    # Main execution logic
    def run(self):
        pozadavky = self.create_out_table_definition('items.csv')
        aktivity = self.create_out_table_definition('activities.csv')

        out_table_path = pozadavky.full_path
        out_table_path2 = aktivity.full_path

        logging.info(out_table_path)
        logging.info(out_table_path2)

        app_id = self.configuration.parameters.get(KEY_APP_ID)

        # Fetch items from Podio with pagination logic
        items = self.get_all_podio_items(app_id, max_items=2500)

        # Filter records from the last 10 days
        items_last_10_days = [
            item for item in items if
            datetime.strptime(item['last_event_on'], '%Y-%m-%d %H:%M:%S') >= datetime.now() - timedelta(days=10)
        ]

        # Transform items and rename columns
        df_podio = self.transform_podio_items(items_last_10_days)

        column_rename_map = {
            'item_id': 'item_id',
            'external_id': 'external_id',
            'request_number': 'request_number',
            'request_link': 'request_link',
            'title': 'title',
            'created_on': 'created_on',
            'last_event_on': 'last_event_on',
            'created_by_name': 'created_by',
            'realizuje_name': 'responsible',
            'stav_text': 'status',
            'datum_zmeny_stavu': 'status_change_date',
            'kontrola_splneni_text': 'requirement_fulfillment_check',
            'oblast_text': 'area',
            'priorita_text': 'priority',
            'schvaleni_text': 'approval',
            'prostredi_text': 'environment',
            'signifikantni_zmena': 'significant_change',
            'poznamky_text': 'notes',
            'files': 'files',
            'tags': 'tags',
            'tasks': 'tasks',
            'jira_project_text': 'jira_project',
            'jira_link': 'jira_link',
            'pozadavek_text': 'requirement',
            'zadani_text': 'assignment',
            'zainteresovane_osoby': 'interested_persons'
        }

        # Rename columns
        df_podio.rename(columns=column_rename_map, inplace=True)
        # Save with semicolon as delimiter
        df_podio.to_csv(out_table_path, sep='\t', index=False)
        logging.info(f"Transformed data saved to {out_table_path}.")

        # Pro každý požadavek načteme aktivity (revize a komentáře)
        all_activities = []
        for item in items_last_10_days:
            activities = self.get_item_revisions_and_comments(item, self.access_token)
            all_activities.extend(activities)

        df_activities = pd.DataFrame(all_activities)
        # Save with semicolon as delimiter
        df_activities.to_csv(out_table_path2, sep='\t', index=False)
        logging.info(f"Activities data saved to {out_table_path2}.")


# Main entry point
if __name__ == "__main__":
    try:
        comp = Component()
        comp.execute_action()
    except keboola.component.exceptions.UserException as exc:
        logging.exception(exc)
        exit(1)
    except Exception as exc:
        logging.exception(exc)
        exit(2)
