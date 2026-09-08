from fastapi import APIRouter, HTTPException

from models.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
)

from services.investigation_services import InvestigationService

from services.gmail_services import (
    GmailService,
    GmailServiceError,
)

from routes.analysis import _analyze_raw_email


router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
)


# ============================================================
# CREATE INVESTIGATION
# ============================================================

@router.post("")
async def create_investigation(
    request: InvestigationCreate,
):
    """
    Create a new investigation case.
    """

    try:
        result = InvestigationService.create_investigation(
            title=request.title,
            description=request.description,
            priority=request.priority,
            analyst=request.analyst,
        )

        return {
            "success": True,
            "message": "Investigation created successfully",
            "data": result,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create investigation: {exc}",
        )


# ============================================================
# LIST INVESTIGATIONS
# ============================================================

@router.get("")
async def list_investigations():
    """
    List all investigation cases.

    The current InvestigationService.list_investigations()
    implementation does not accept filters or pagination
    parameters, so this route intentionally calls it without
    arguments and wraps the returned list in an API response.
    """

    try:
        result = InvestigationService.list_investigations()

        return {
            "success": True,
            "investigations": result,
            "count": len(result),
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list investigations: {exc}",
        )


# ============================================================
# GET COMPLETE INVESTIGATION
# ============================================================

@router.get("/{case_id}")
async def get_investigation(
    case_id: str,
):
    """
    Get a complete investigation including:

    - case metadata
    - analyzed emails
    - findings
    - IOCs
    - risk information
    """

    try:
        result = InvestigationService.get_investigation(
            case_id
        )

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "data": result,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get investigation: {exc}",
        )


# ============================================================
# UPDATE INVESTIGATION
# ============================================================

@router.patch("/{case_id}")
async def update_investigation(
    case_id: str,
    request: InvestigationUpdate,
):
    """
    Update an existing investigation case.
    """

    try:
        result = InvestigationService.update_investigation(
            case_id,
            title=request.title,
            description=request.description,
            priority=request.priority,
            status=request.status,
            analyst=request.analyst,
            notes=request.notes,
        )

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "message": "Investigation updated successfully",
            "data": result,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to update investigation: {exc}",
        )


# ============================================================
# DELETE INVESTIGATION
# ============================================================

@router.delete("/{case_id}")
async def delete_investigation(
    case_id: str,
):
    """
    Delete an investigation case.
    """

    try:
        result = InvestigationService.delete_investigation(
            case_id
        )

        if not result:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        return {
            "success": True,
            "message": "Investigation deleted successfully",
            "case_id": case_id,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete investigation: {exc}",
        )


# ============================================================
# ANALYZE GMAIL MESSAGE INSIDE INVESTIGATION
# ============================================================

@router.post("/{case_id}/gmail/{message_id}/analyze")
async def analyze_gmail_message_for_investigation(
    case_id: str,
    message_id: str,
):
    """
    Fetch a Gmail message, analyze it using the existing
    email analysis pipeline, and associate the analysis
    with an investigation.

    This uses the existing Gmail service and analysis engine.
    """

    try:
        investigation = InvestigationService.get_investigation(
            case_id
        )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail=f"Investigation '{case_id}' not found",
            )

        gmail = GmailService()

        raw_email = gmail.get_raw_message(
            message_id
        )

        if not raw_email:
            raise HTTPException(
                status_code=404,
                detail=f"Gmail message '{message_id}' not found",
            )

        result = _analyze_raw_email(
            raw_email
        )

        result["gmail"] = {
            "message_id": message_id,
        }

        result["investigation"] = {
            "case_id": case_id,
        }

        return {
            "success": True,
            "case_id": case_id,
            "message_id": message_id,
            "analysis": result,
        }

    except HTTPException:
        raise

    except GmailServiceError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Gmail service error: {exc}",
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to analyze Gmail message "
                f"for investigation: {exc}"
            ),
        )