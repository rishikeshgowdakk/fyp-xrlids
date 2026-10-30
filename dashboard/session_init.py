"""Session state initializer for XRL-IDARS Streamlit dashboard."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

import streamlit as st

from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline


def ensure_session_state() -> tuple[EventManager, ActiveInferencePipeline, LiveCaptureManager]:
    """Ensure global session state is initialized cleanly without automatic traffic generation.
    
    On initial launch:
    - Initialize components
    - Check and report actual capture permissions
    - Maintain empty event state
    - Zero background live capture without explicit user action
    """
    if "event_manager" not in st.session_state:
        st.session_state.event_manager = EventManager()
    if "pipeline" not in st.session_state:
        st.session_state.pipeline = ActiveInferencePipeline(
            event_manager=st.session_state.event_manager,
            explain_all=True,
        )
    if "live_manager" not in st.session_state:
        st.session_state.live_manager = LiveCaptureManager(
            pipeline=st.session_state.pipeline,
            event_manager=st.session_state.event_manager,
        )
    if "replayed_flows" not in st.session_state:
        st.session_state.replayed_flows = []

    event_mgr: EventManager = st.session_state.event_manager
    pipeline: ActiveInferencePipeline = st.session_state.pipeline
    live_mgr: LiveCaptureManager = st.session_state.live_manager

    return event_mgr, pipeline, live_mgr
