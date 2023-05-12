#!/usr/bin/env python3
import requests
import json

def incomingWebhook(url, message):
	try:
		data = {
				"blocks": [
				{
					"type": "section",
					"text": {
						"type": "mrkdwn",
						"text": message
					}
				},
				{
                        "type": "divider"
                }
			]
		}

		requests.post(url, headers = { 'Content-type' : 'application/json' }, data = json.dumps(data))
	except Exception as e:
		print('No se pudo enviar el mensaje a Slack: {}'.format(e))