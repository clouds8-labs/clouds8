"""
Clouds8 Backend API - Object storage download proxy

Streams a single object from the cloud provider's object storage straight
through to the caller. Exists so the Integration Service (ui/app.py's
/download-object route) never has to instantiate a cloud SDK collector
itself just to let a user download one flagged file.
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from collector import build_collector

router = APIRouter(prefix="/objects", tags=["objects"])


@router.get("/download")
def download_object(
    ns: str = Query(..., description="Object storage namespace"),
    bucket: str = Query(...),
    object: str = Query(...),
    region: str = Query(None),
    provider: str = Query("oci"),
):
    collector = build_collector(provider)
    if collector is None:
        raise HTTPException(503, f"{provider} is not configured")

    try:
        if region:
            collector.setup_regional_clients(region)
        client = collector.get_client("object_storage")
        response = client.get_object(namespace_name=ns, bucket_name=bucket, object_name=object)
    except Exception as e:
        raise HTTPException(502, f"Download failed: {e}")

    content_type = response.headers.get("Content-Type", "application/octet-stream")

    def generate():
        for chunk in response.data.raw.stream(1024 * 1024):
            yield chunk

    return StreamingResponse(generate(), media_type=content_type)
