import os
import re
import sys
import base64
import requests
import time
from datetime import datetime
from bs4 import BeautifulSoup as BS

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
last_message_id = None
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def set_last_message_id():
    # Get the last message ID from the PDFs folder
    if os.path.exists("kindle-pdfs"):
        pdfs = os.listdir("kindle-pdfs")
        if pdfs:
            pdfs.sort(key=lambda x: float(x.split("_")[1]))
            return pdfs[-1].split("_")[2].split(".")[0]

def auth():
    global SCOPES
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        print(f"[*] No valid token.json found...")
        if creds and creds.expired and creds.refresh_token:
            print("[*] Refreshing credentials, please wait...")
            creds.refresh(Request())
        else:
            print()
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open("token.json", "w") as token:
                token.write(creds.to_json())
    return creds

def fetch_pdf(pdf_link, filename):
    # Download the PDF
    try:
        response = requests.get(pdf_link)
        with open(f"kindle-pdfs/{filename}.pdf", "wb") as pdf:
            pdf.write(response.content)
    except Exception as err:
        print("[!] Something went wrong while downloading {filename}.pdf:\n{err}")
        sys.exit(2)

def main(creds):
    global last_message_id
    try:
        # Call the Gmail API
        service = build("gmail", "v1", credentials=creds)

        # Get the last email from <do-not-reply@amazon.com>
        results = (
            service.users()
            .messages()
            .list(userId="me", q="from:do-not-reply@amazon.com", maxResults=1)
            .execute()
        )
        # Store the whole message
        message = (
            service.users()
            .messages()
            .get(userId="me", id=results["messages"][0]["id"])
            .execute()
        )


        # If the last message is the same as the previous one, return
        if last_message_id == None:
            last_message_id = results["messages"][0]["id"]
            return
        if last_message_id == results["messages"][0]["id"]:
            return
        last_message_id = results["messages"][0]["id"]
        print("[*] Found new Kindle PDF, now downloading...")

        b64content = "".join(part["body"]["data"] for part in message["payload"]["parts"] if part["mimeType"] == "text/html")
        content = base64.urlsafe_b64decode(b64content).decode("utf-8")
        soup = BS(content, "html.parser")
        anchor = [a for a in soup.find_all('a') if "Download PDF" == a.text]

        if len(anchor) != 1:
            return

        pdf_link = str(anchor[0].get("href"))
        # Set the filename to the current time and the message ID
        filename = f"{message["snippet"].split("&quot;")[1].replace(" ", "-")}_{time.time()}_{results['messages'][0]['id']}"
        # Download the PDF
        fetch_pdf(pdf_link, filename)
        print(f"[+] Downloaded to kindle-pdfs/{filename}.pdf")

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f"An error occurred: {error}")


if __name__ == "__main__":
    print(f"[*] Checking OAuth2.0 Modules...")
    if not os.path.isfile("credentials.json"):
        print(f"[!] Credentials file missing, if present rename it to credentails.json an place it in this directory")
        sys.exit(1)
    creds = auth()

    if not os.path.exists("kindle-pdfs"):
        os.mkdir("kindle-pdfs")

    last_message_id = set_last_message_id()
    while True:
        now = datetime.now()
        print(f"[*] Checking GMail inbox at {now.strftime('%Y-%m-%d %H:%M:%S')}...")
        main(creds)
        time.sleep(2)
