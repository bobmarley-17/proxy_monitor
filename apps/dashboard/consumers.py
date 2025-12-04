import json
from channels.generic.websocket import AsyncWebsocketConsumer


class DashboardConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add('dashboard', self.channel_name)
        await self.accept()
        # DO NOT send initial data - view handles it

    async def disconnect(self, code):
        await self.channel_layer.group_discard('dashboard', self.channel_name)

    async def new_request(self, event):
        await self.send(text_data=json.dumps({
            'type': 'new_request',
            'request': event['request']
        }))

    async def stats_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'stats_update',
            'stats': event['stats']
        }))
