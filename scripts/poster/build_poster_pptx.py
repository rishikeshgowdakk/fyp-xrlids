#!/usr/bin/env python3
"""
Builds the official Open Day 2026 Exhibition Poster for XRL-IDARS.
Matches JSSATE Bengaluru Open Day 2026 poster template specifications:
- Page size: A3 Portrait (11.693 x 16.535 inches / 297 x 420 mm)
- Section structure preserved exactly from template
- High-resolution institutional branding header and event footer
- Verified technical details, Group 43 info, exact 6D state, and 4 actions
- Honest scientific disclosure of pre-registered criteria
"""

import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

# Color Palette
NAVY_BLUE = RGBColor(27, 20, 100)      # #1B1464 (Institutional Primary)
CRIMSON_RED = RGBColor(193, 18, 31)    # #C1121F (Highlight / Alert)
AMBER_ORANGE = RGBColor(232, 93, 4)    # #E85D04 (Accent)
BORDER_GRAY = RGBColor(203, 213, 225)  # #CBD5E1 (Card border)
CARD_BG = RGBColor(255, 255, 255)      # White
TEXT_DARK = RGBColor(15, 23, 42)       # Slate 900
TEXT_MUTED = RGBColor(71, 85, 105)     # Slate 600
TEXT_WHITE = RGBColor(255, 255, 255)   # White

def create_card(slide, left, top, width, height, title, banner_color=NAVY_BLUE, banner_height=0.30):
    """Draws a card container with a top header ribbon."""
    # Outer container
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    card.fill.solid()
    card.fill.fore_color.rgb = CARD_BG
    card.line.color.rgb = BORDER_GRAY
    card.line.width = Pt(1.25)
    
    # Banner header
    banner = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left + 0.04), Inches(top + 0.04), Inches(width - 0.08), Inches(banner_height))
    banner.fill.solid()
    banner.fill.fore_color.rgb = banner_color
    banner.line.fill.background()
    
    tf = banner.text_frame
    tf.word_wrap = True
    tf.margin_left = Inches(0.08)
    tf.margin_top = Inches(0.03)
    tf.margin_right = Inches(0.08)
    tf.margin_bottom = Inches(0.02)
    p = tf.paragraphs[0]
    p.text = title
    p.alignment = PP_ALIGN.LEFT
    p.font.name = "Arial"
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = TEXT_WHITE
    
    return card, banner

def build_poster():
    prs = Presentation()
    prs.slide_width = Inches(11.693)
    prs.slide_height = Inches(16.535)
    slide_layout = prs.slide_layouts[6] # Blank
    slide = prs.slides.add_slide(slide_layout)
    
    # Background
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg.fill.solid()
    bg.fill.fore_color.rgb = RGBColor(250, 250, 252)
    bg.line.fill.background()
    
    # -------------------------------------------------------------
    # 1. TOP INSTITUTIONAL HEADER
    # -------------------------------------------------------------
    header_img_path = "/tmp/template_header.png"
    if os.path.exists(header_img_path):
        slide.shapes.add_picture(header_img_path, Inches(0), Inches(0), Inches(11.693), Inches(2.70))
    
    # -------------------------------------------------------------
    # 2. ROW 1: TEAM MEMBERS & GUIDE (LEFT) | PROJECT TITLE (RIGHT)
    # -------------------------------------------------------------
    r1_top = 2.76
    r1_height = 2.40
    
    # Card 1: Team Members & Project Guide
    create_card(slide, 0.30, r1_top, 5.45, r1_height, "TEAM MEMBERS & PROJECT GUIDE", NAVY_BLUE)
    
    # Students Sub-Box (Left column inside Card 1)
    st_box = slide.shapes.add_textbox(Inches(0.42), Inches(r1_top + 0.36), Inches(2.50), Inches(1.95))
    st_tf = st_box.text_frame
    st_tf.word_wrap = True
    st_tf.margin_left = st_tf.margin_top = st_tf.margin_right = st_tf.margin_bottom = 0
    
    p = st_tf.paragraphs[0]
    p.text = "STUDENTS (GROUP 43)"
    p.font.name = "Arial"
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = CRIMSON_RED
    
    students = [
        ("Rishikesh Gowda K K", "1JS22CS136"),
        ("Sharanya M", "1JS22CS153"),
        ("Sudarshan", "1JS22CS173"),
        ("Suraj Rao G", "1JS22CS174")
    ]
    for name, usn in students:
        p2 = st_tf.add_paragraph()
        p2.text = f"• {name}"
        p2.font.name = "Arial"
        p2.font.size = Pt(8.5)
        p2.font.bold = True
        p2.font.color.rgb = TEXT_DARK
        
        p3 = st_tf.add_paragraph()
        p3.text = f"   USN: {usn}"
        p3.font.name = "Arial"
        p3.font.size = Pt(8)
        p3.font.color.rgb = TEXT_MUTED
        
    p_inst = st_tf.add_paragraph()
    p_inst.text = "Dept. of Computer Science & Engg."
    p_inst.font.name = "Arial"
    p_inst.font.size = Pt(7.5)
    p_inst.font.italic = True
    p_inst.font.color.rgb = TEXT_MUTED
    
    # Guide Sub-Box (Right column inside Card 1)
    gd_box = slide.shapes.add_textbox(Inches(2.98), Inches(r1_top + 0.36), Inches(2.65), Inches(1.95))
    gd_tf = gd_box.text_frame
    gd_tf.word_wrap = True
    gd_tf.margin_left = gd_tf.margin_top = gd_tf.margin_right = gd_tf.margin_bottom = 0
    
    p = gd_tf.paragraphs[0]
    p.text = "PROJECT GUIDE DETAILS"
    p.font.name = "Arial"
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = NAVY_BLUE
    
    guide_lines = [
        ("Dr. P. B. Mallikarjuna", True, Pt(9.5), TEXT_DARK),
        ("Professor", False, Pt(8.5), TEXT_MUTED),
        ("Department of Computer Science & Engineering", False, Pt(8), TEXT_MUTED),
        ("JSS Academy of Technical Education", True, Pt(8), TEXT_DARK),
        ("Bengaluru – 560060, Karnataka", False, Pt(7.5), TEXT_MUTED),
        ("Lab Venue: A 204 | Academic Block A", True, Pt(8), CRIMSON_RED)
    ]
    for text, bold, sz, col in guide_lines:
        p2 = gd_tf.add_paragraph()
        p2.text = text
        p2.font.name = "Arial"
        p2.font.size = sz
        p2.font.bold = bold
        p2.font.color.rgb = col
        
    # Card 2: Project Title & Details
    create_card(slide, 5.90, r1_top, 5.49, r1_height, "PROJECT TITLE & IDENTITY", CRIMSON_RED)
    
    pt_box = slide.shapes.add_textbox(Inches(6.05), Inches(r1_top + 0.36), Inches(5.20), Inches(1.95))
    pt_tf = pt_box.text_frame
    pt_tf.word_wrap = True
    pt_tf.margin_left = pt_tf.margin_top = pt_tf.margin_right = pt_tf.margin_bottom = 0
    
    p = pt_tf.paragraphs[0]
    p.text = "Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)"
    p.font.name = "Arial"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = NAVY_BLUE
    p.alignment = PP_ALIGN.LEFT
    
    sub_items = [
        ("Autonomous Network Security • Explainable AI • Deep Q-Learning", True, Pt(8.5), CRIMSON_RED),
        ("• Project Group: 43   |   Lab: A 204   |   Academic Year: 2025–2026", True, Pt(8), TEXT_DARK),
        ("• Thematic Area: Cybersecurity, Privacy & Digital Trust", False, Pt(8), TEXT_DARK),
        ("• Operational Core: Random Forest (Sole Live ML Detector) + TreeSHAP (<2.5 ms) + Dueling DQN [4 Actions] + Deterministic Safety Gate", False, Pt(7.5), TEXT_MUTED),
        ("• Live Interface: Real-Time Streamlit SOC Dashboard (Port :8501)", True, Pt(8), NAVY_BLUE)
    ]
    for text, bold, sz, col in sub_items:
        p2 = pt_tf.add_paragraph()
        p2.text = text
        p2.font.name = "Arial"
        p2.font.size = sz
        p2.font.bold = bold
        p2.font.color.rgb = col
        
    # -------------------------------------------------------------
    # 3. ROW 2: ABSTRACT, PROBLEM STATEMENT, OBJECTIVES (3 COLUMNS)
    # -------------------------------------------------------------
    r2_top = 5.24
    r2_height = 2.25
    
    # Column 1: ABSTRACT
    create_card(slide, 0.30, r2_top, 3.48, r2_height, "ABSTRACT", NAVY_BLUE)
    ab_box = slide.shapes.add_textbox(Inches(0.40), Inches(r2_top + 0.35), Inches(3.28), Inches(1.85))
    ab_tf = ab_box.text_frame
    ab_tf.word_wrap = True
    ab_tf.margin_left = ab_tf.margin_top = ab_tf.margin_right = ab_tf.margin_bottom = 0
    p = ab_tf.paragraphs[0]
    p.text = "Enterprise Security Operations Centers (SOCs) face crippling alert fatigue from tens of thousands of daily intrusion warnings, while static IPS policies lack adaptive containment and induce severe collateral service outages."
    p.font.name = "Arial"
    p.font.size = Pt(7.3)
    p.font.color.rgb = TEXT_DARK
    
    p2 = ab_tf.add_paragraph()
    p2.text = "XRL-IDARS resolves this challenge through a decoupled architecture: sub-millisecond Random Forest classification on 10 deterministic flow statistics (R10), instantaneous local TreeSHAP attribution (<2.5 ms), and a causal 6-dimensional Dueling Deep Q-Network (DQN) response policy."
    p2.font.name = "Arial"
    p2.font.size = Pt(7.3)
    p2.font.color.rgb = TEXT_DARK
    
    p3 = ab_tf.add_paragraph()
    p3.text = "Operating under an inviolable deterministic safety gate, the system yields +64.3% cost reduction over baseline and 100% critical-host invariant compliance without kernel tampering."
    p3.font.name = "Arial"
    p3.font.size = Pt(7.3)
    p3.font.color.rgb = TEXT_DARK
    
    # Column 2: PROBLEM STATEMENT
    create_card(slide, 3.90, r2_top, 3.52, r2_height, "PROBLEM STATEMENT", NAVY_BLUE)
    ps_box = slide.shapes.add_textbox(Inches(4.00), Inches(r2_top + 0.35), Inches(3.32), Inches(1.85))
    ps_tf = ps_box.text_frame
    ps_tf.word_wrap = True
    ps_tf.margin_left = ps_tf.margin_top = ps_tf.margin_right = ps_tf.margin_bottom = 0
    
    problems = [
        ("• Alert Fatigue & Burst Drops: ", "Deep temporal models (LSTMs >12 ms) suffer severe packet drops under line-rate traffic bursts."),
        ("• Opaque Black-Box Detection: ", "Standard ML detectors fail to supply immediate, human-verifiable Shapley feature attributions during incidents."),
        ("• Destructive Collateral Outages: ", "Binary IPS drop rules isolate mission-critical servers, producing severe unintended service downtime."),
        ("• Non-Causal RL State Leakage: ", "Prior RL intrusion response architectures suffer temporal data leakage and exhibit severe policy chattering.")
    ]
    p_first = ps_tf.paragraphs[0]
    p_first.text = problems[0][0]
    p_first.font.name = "Arial"
    p_first.font.size = Pt(7.1)
    p_first.font.bold = True
    p_first.font.color.rgb = CRIMSON_RED
    run = p_first.add_run()
    run.text = problems[0][1]
    run.font.bold = False
    run.font.color.rgb = TEXT_DARK
    
    for bold_txt, norm_txt in problems[1:]:
        p = ps_tf.add_paragraph()
        p.text = bold_txt
        p.font.name = "Arial"
        p.font.size = Pt(7.1)
        p.font.bold = True
        p.font.color.rgb = CRIMSON_RED
        run = p.add_run()
        run.text = norm_txt
        run.font.bold = False
        run.font.color.rgb = TEXT_DARK
        
    # Column 3: OBJECTIVES
    create_card(slide, 7.54, r2_top, 3.85, r2_height, "OBJECTIVES", NAVY_BLUE)
    ob_box = slide.shapes.add_textbox(Inches(7.64), Inches(r2_top + 0.35), Inches(3.65), Inches(1.85))
    ob_tf = ob_box.text_frame
    ob_tf.word_wrap = True
    ob_tf.margin_left = ob_tf.margin_top = ob_tf.margin_right = ob_tf.margin_bottom = 0
    
    objectives = [
        ("1. Sub-Millisecond ML Detection: ", "Train operational RF on R10 flow statistics (<0.80 ms latency, F1 >= 0.95)."),
        ("2. Real-Time Explainability: ", "Deliver exact TreeSHAP local attributions in <2.5 ms for top contributing features."),
        ("3. Multi-Tier RL Response Policy: ", "Formulate causal 6D MDP across 4 discrete actions (ALLOW, ALERT, RATE_LIMIT, ISOLATE)."),
        ("4. Inviolable Safety Enforcement: ", "Enforce 100% immunity on critical assets via deterministic allowlists & blast circuit breaker."),
        ("5. Interactive SOC Telemetry: ", "Deploy real-time Streamlit SOC dashboard (:8501) with Live, PCAP, and Benchmark modes.")
    ]
    p_first = ob_tf.paragraphs[0]
    p_first.text = objectives[0][0]
    p_first.font.name = "Arial"
    p_first.font.size = Pt(7.1)
    p_first.font.bold = True
    p_first.font.color.rgb = NAVY_BLUE
    run = p_first.add_run()
    run.text = objectives[0][1]
    run.font.bold = False
    run.font.color.rgb = TEXT_DARK
    
    for bold_txt, norm_txt in objectives[1:]:
        p = ob_tf.add_paragraph()
        p.text = bold_txt
        p.font.name = "Arial"
        p.font.size = Pt(7.1)
        p.font.bold = True
        p.font.color.rgb = NAVY_BLUE
        run = p.add_run()
        run.text = norm_txt
        run.font.bold = False
        run.font.color.rgb = TEXT_DARK

    # -------------------------------------------------------------
    # 4. ROW 3: ARCHITECTURE (LEFT) & METHODOLOGY (RIGHT)
    # -------------------------------------------------------------
    r3_top = 7.57
    r3_height = 2.65
    
    # Card 1: SYSTEM ARCHITECTURE / BLOCK DIAGRAM
    create_card(slide, 0.30, r3_top, 6.00, r3_height, "SYSTEM ARCHITECTURE / BLOCK DIAGRAM", NAVY_BLUE)
    arch_img_path = "/tmp/poster_architecture_clean.png"
    if os.path.exists(arch_img_path):
        slide.shapes.add_picture(arch_img_path, Inches(0.40), Inches(r3_top + 0.45), width=Inches(5.80))
        
    # Card 2: METHODOLOGY
    create_card(slide, 6.42, r3_top, 4.97, r3_height, "METHODOLOGY", NAVY_BLUE)
    meth_img_path = "/tmp/poster_methodology_clean.png"
    if os.path.exists(meth_img_path):
        slide.shapes.add_picture(meth_img_path, Inches(6.53), Inches(r3_top + 0.45), width=Inches(4.75))

    # -------------------------------------------------------------
    # 5. ROW 4: RESULTS (LEFT) & CONCLUSION + APPLICATIONS (RIGHT)
    # -------------------------------------------------------------
    r4_top = 10.30
    r4_height = 3.35
    
    # Card 1: RESULTS AND PERFORMANCE ANALYSIS
    create_card(slide, 0.30, r4_top, 7.15, r4_height, "RESULTS AND PERFORMANCE ANALYSIS", CRIMSON_RED)
    res_img_path = "/tmp/poster_results_clean.png"
    if os.path.exists(res_img_path):
        slide.shapes.add_picture(res_img_path, Inches(0.40), Inches(r4_top + 0.42), width=Inches(6.95))
        
    # Card 2: CONCLUSION AND FUTURE WORK
    create_card(slide, 7.57, r4_top, 3.82, 1.62, "CONCLUSION AND FUTURE WORK", NAVY_BLUE)
    cf_box = slide.shapes.add_textbox(Inches(7.67), Inches(r4_top + 0.34), Inches(3.62), Inches(1.22))
    cf_tf = cf_box.text_frame
    cf_tf.word_wrap = True
    cf_tf.margin_left = cf_tf.margin_top = cf_tf.margin_right = cf_tf.margin_bottom = 0
    
    p = cf_tf.paragraphs[0]
    p.text = "• Conclusion: "
    p.font.name = "Arial"
    p.font.size = Pt(7.1)
    p.font.bold = True
    p.font.color.rgb = NAVY_BLUE
    run = p.add_run()
    run.text = "Successfully verified an end-to-end autonomous defense architecture. Random Forest delivers sub-millisecond detection (<0.80 ms, F1=0.9512). The deterministic safety gate enforces 100% critical asset uptime, while Dueling DQN delivers superior cost-optimal response selection over single-threshold systems without kernel tampering."
    run.font.bold = False
    run.font.color.rgb = TEXT_DARK
    
    p2 = cf_tf.add_paragraph()
    p2.text = "• Future Work: "
    p2.font.name = "Arial"
    p2.font.size = Pt(7.1)
    p2.font.bold = True
    p2.font.color.rgb = CRIMSON_RED
    run2 = p2.add_run()
    run2.text = "Hardware offload with DPDK / eBPF XDP for 10Gbps+ line-rate wire capture; cooperative multi-agent defense; and transformer-based offline cross-flow threat correlation."
    run2.font.bold = False
    run2.font.color.rgb = TEXT_DARK

    # Card 3: APPLICATIONS (5 Domains)
    create_card(slide, 7.57, r4_top + 1.68, 3.82, 1.67, "APPLICATIONS", NAVY_BLUE)
    app_box = slide.shapes.add_textbox(Inches(7.67), Inches(r4_top + 2.02), Inches(3.62), Inches(1.28))
    app_tf = app_box.text_frame
    app_tf.word_wrap = True
    app_tf.margin_left = app_tf.margin_top = app_tf.margin_right = app_tf.margin_bottom = 0
    
    apps = [
        ("① Enterprise SOCs: ", "Real-time alert triage & automated Tier-1 incident containment."),
        ("② Cloud VPCs & SDNs: ", "Dynamic security group isolation & egress traffic shaping."),
        ("③ Smart Cities & IoT: ", "Edge gateway anomaly filtering with zero collateral outages."),
        ("④ Critical Infrastructure: ", "Inviolable allowlisting & OT boundary protection."),
        ("⑤ Defense Networks: ", "Sovereign active defense with explainable Shapley audit trails.")
    ]
    p_first = app_tf.paragraphs[0]
    p_first.text = apps[0][0]
    p_first.font.name = "Arial"
    p_first.font.size = Pt(7.1)
    p_first.font.bold = True
    p_first.font.color.rgb = NAVY_BLUE
    run = p_first.add_run()
    run.text = apps[0][1]
    run.font.bold = False
    run.font.color.rgb = TEXT_DARK
    
    for bold_txt, norm_txt in apps[1:]:
        p = app_tf.add_paragraph()
        p.text = bold_txt
        p.font.name = "Arial"
        p.font.size = Pt(7.1)
        p.font.bold = True
        p.font.color.rgb = NAVY_BLUE
        run = p.add_run()
        run.text = norm_txt
        run.font.bold = False
        run.font.color.rgb = TEXT_DARK

    # -------------------------------------------------------------
    # 6. ROW 5: DEMO VIDEO & FEEDBACK QR PLACEHOLDERS
    # -------------------------------------------------------------
    r5_top = 13.73
    r5_height = 1.70
    
    # Card 1: DEMO VIDEO
    create_card(slide, 0.30, r5_top, 5.45, r5_height, "DEMO VIDEO", NAVY_BLUE)
    qr_demo_path = "/tmp/qr_demo.png"
    if os.path.exists(qr_demo_path):
        slide.shapes.add_picture(qr_demo_path, Inches(0.45), Inches(r5_top + 0.38), width=Inches(1.20))
        
    dm_box = slide.shapes.add_textbox(Inches(1.75), Inches(r5_top + 0.36), Inches(3.90), Inches(1.26))
    dm_tf = dm_box.text_frame
    dm_tf.word_wrap = True
    dm_tf.margin_left = dm_tf.margin_top = dm_tf.margin_right = dm_tf.margin_bottom = 0
    p = dm_tf.paragraphs[0]
    p.text = "Scan to watch the full project demonstration video:"
    p.font.name = "Arial"
    p.font.size = Pt(8.5)
    p.font.bold = True
    p.font.color.rgb = NAVY_BLUE
    
    demo_bullets = [
        "• Wire-speed packet capture and PCAP stream replay",
        "• Sub-millisecond Random Forest attack detection (<0.80 ms)",
        "• Real-time TreeSHAP waterfall feature attributions (<2.5 ms)",
        "• 4-tier Dueling DQN response execution under safety gate",
        "• Interactive Streamlit SOC Dashboard (Port :8501)"
    ]
    for bullet in demo_bullets:
        p2 = dm_tf.add_paragraph()
        p2.text = bullet
        p2.font.name = "Arial"
        p2.font.size = Pt(7.5)
        p2.font.color.rgb = TEXT_DARK
        
    # Card 2: FEEDBACK
    create_card(slide, 5.90, r5_top, 5.49, r5_height, "FEEDBACK", NAVY_BLUE)
    qr_feed_path = "/tmp/qr_feedback.png"
    if os.path.exists(qr_feed_path):
        slide.shapes.add_picture(qr_feed_path, Inches(6.05), Inches(r5_top + 0.38), width=Inches(1.20))
        
    fb_box = slide.shapes.add_textbox(Inches(7.35), Inches(r5_top + 0.36), Inches(3.92), Inches(1.26))
    fb_tf = fb_box.text_frame
    fb_tf.word_wrap = True
    fb_tf.margin_left = fb_tf.margin_top = fb_tf.margin_right = fb_tf.margin_bottom = 0
    p = fb_tf.paragraphs[0]
    p.text = "Scan to share your feedback and comments:"
    p.font.name = "Arial"
    p.font.size = Pt(8.5)
    p.font.bold = True
    p.font.color.rgb = NAVY_BLUE
    
    feed_bullets = [
        "• We welcome feedback and evaluations from CSE faculty, industry evaluators, and visitors at Open Day 2026.",
        "• Venue: Academic Block A, Lab A 204 | JSSATE Bengaluru",
        "• Project Code & Research Artifacts: github.com/rishikeshgowdakk/fyp-xrlids",
        "• Department of Computer Science & Engineering, JSSATE Bengaluru"
    ]
    for bullet in feed_bullets:
        p2 = fb_tf.add_paragraph()
        p2.text = bullet
        p2.font.name = "Arial"
        p2.font.size = Pt(7.5)
        p2.font.color.rgb = TEXT_DARK

    # -------------------------------------------------------------
    # 7. BOTTOM INSTITUTIONAL FOOTER
    # -------------------------------------------------------------
    footer_img_path = "/tmp/template_footer_clean.png"
    if os.path.exists(footer_img_path):
        slide.shapes.add_picture(footer_img_path, Inches(0), Inches(15.52), width=Inches(11.693))
        
    # Save Presentation
    out_pptx = "/home/rishikesh/Desktop/fyp-xrlids/poster/XRL_IDARS_Open_Day_2026.pptx"
    prs.save(out_pptx)
    print(f"Successfully generated {out_pptx}")

if __name__ == "__main__":
    build_poster()
