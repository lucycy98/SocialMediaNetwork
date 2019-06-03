import database
import time
import database

conversations = database.getConversation("lche982", "admin")
print(conversations)

for conversation in conversations:
    if conversations.get("sent") == 'sent':
        
