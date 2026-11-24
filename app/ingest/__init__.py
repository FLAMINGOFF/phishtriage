"""Intake channels: IMAP report mailbox, web upload and REST API.

Every channel does the same small job: store the raw message, create a report row and
put the report ID on the queue. Parsing never happens here (see app.worker).
"""
