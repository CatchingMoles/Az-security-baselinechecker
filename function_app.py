import azure.functions as func
import logging
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
import datetime
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="AuditReceiver", methods=["POST"])
def AuditReceiver(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('AuditReceiver: Verwerking via Managed Identity gestart.')

    try:
        encrypted_payload = req.get_body()
        if not encrypted_payload:
            return func.HttpResponse("Geen data ontvangen", status_code=400)

        # 1. Gebruik de URL van je storage account (bijv. https://account.blob.core.windows.net)
        # Deze zetten we dadelijk in de App Settings
        account_url = os.getenv('AUDIT_STORAGE_URL')
        
        # 2. De 'Magic': DefaultAzureCredential pakt automatisch de Managed Identity op
        token_credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(account_url=account_url, credential=token_credential)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"audit-{timestamp}.encrypted"

        blob_client = blob_service_client.get_blob_client(container="incoming-audits", blob=filename)
        blob_client.upload_blob(encrypted_payload, overwrite=True)

        return func.HttpResponse("OK: Veilig opgeslagen via Managed Identity.", status_code=200)

    except Exception as e:
        logging.error(f"Fout: {str(e)}")
        return func.HttpResponse(f"Fout: {str(e)}", status_code=500)