#!/usr/bin/env python3
"""
Generate comprehensive PDF documentation for Arcade Tracker
"""

import sys
import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from datetime import datetime

def create_documentation():
    """Generate comprehensive PDF documentation"""
    
    # Create PDF document
    filename = "Arcade_Tracker_Documentation.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter, 
                           topMargin=0.75*inch, bottomMargin=0.75*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.darkblue,
        alignment=TA_CENTER
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.darkblue,
        spaceBefore=20
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10,
        textColor=colors.darkblue,
        spaceBefore=15
    )
    
    heading3_style = ParagraphStyle(
        'CustomHeading3',
        parent=styles['Heading3'],
        fontSize=12,
        spaceAfter=8,
        textColor=colors.darkblue,
        spaceBefore=12
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        alignment=TA_JUSTIFY
    )
    
    bullet_style = ParagraphStyle(
        'CustomBullet',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=4,
        leftIndent=20
    )
    
    # Build document content
    story = []
    
    # Title Page
    story.append(Paragraph("🎮 Arcade Tracker", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Comprehensive Arcade Management System", styles['Heading2']))
    story.append(Paragraph("with Advanced Work Logging", styles['Heading2']))
    story.append(Spacer(1, 0.5*inch))
    
    # Version info
    story.append(Paragraph(f"<b>Version:</b> 2.0", body_style))
    story.append(Paragraph(f"<b>Documentation Date:</b> {datetime.now().strftime('%Y-%m-%d')}", body_style))
    story.append(Spacer(1, 0.5*inch))
    
    # Abstract
    abstract_text = """
    Arcade Tracker is a comprehensive management system designed for arcade operators, technicians, 
    and business managers. It provides complete game inventory management, revenue tracking, and an 
    advanced maintenance system with timestamped work logging capabilities. This documentation covers 
    all features, user roles, workflows, and technical details.
    """
    story.append(Paragraph("<b>Abstract</b>", heading2_style))
    story.append(Paragraph(abstract_text, body_style))
    
    story.append(PageBreak())
    
    # Table of Contents
    story.append(Paragraph("Table of Contents", heading1_style))
    toc_data = [
        ["Section", "Page"],
        ["1. System Overview", "3"],
        ["2. Features & Capabilities", "4"],
        ["3. User Roles & Permissions", "6"],
        ["4. Work Logging System", "7"],
        ["5. Workflows & Procedures", "9"],
        ["6. Reporting & Analytics", "11"],
        ["7. Technical Architecture", "12"],
        ["8. Getting Started", "13"],
        ["9. Troubleshooting", "14"],
    ]
    
    toc_table = Table(toc_data, colWidths=[4*inch, 1*inch])
    toc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(toc_table)
    story.append(PageBreak())
    
    # Section 1: System Overview
    story.append(Paragraph("1. System Overview", heading1_style))
    
    overview_text = """
    Arcade Tracker is a web-based application built with Flask that provides comprehensive management 
    capabilities for arcade operations. The system is designed to handle everything from basic game 
    inventory to complex maintenance workflows with detailed work logging.
    """
    story.append(Paragraph(overview_text, body_style))
    
    story.append(Paragraph("Key Benefits", heading2_style))
    benefits = [
        "Complete game inventory and location tracking",
        "Automated revenue calculation from coin counts", 
        "Professional work order management with timestamped logging",
        "Role-based access control with hierarchical permissions",
        "Comprehensive reporting with PDF export capabilities",
        "Secure, CSRF-protected web interface"
    ]
    
    for benefit in benefits:
        story.append(Paragraph(f"• {benefit}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 2: Features & Capabilities
    story.append(Paragraph("2. Features & Capabilities", heading1_style))
    
    # Game Management
    story.append(Paragraph("2.1 Game Management", heading2_style))
    game_features = [
        "<b>Game Inventory:</b> Track detailed information including manufacturer, year, genre, and status",
        "<b>Location Tracking:</b> Monitor games across Floor, Warehouse, and Shipped locations with specific positions",
        "<b>Status Management:</b> Track operational status (Working, Being Fixed, Not Working, Retired)",
        "<b>Image Support:</b> Upload and display cabinet photos for visual identification",
        "<b>Revenue Analytics:</b> Automatic calculation of plays and revenue from coin counter readings"
    ]
    
    for feature in game_features:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    # Maintenance System
    story.append(Paragraph("2.2 Advanced Maintenance System", heading2_style))
    
    story.append(Paragraph("Work Order Management", heading3_style))
    maintenance_features = [
        "Create detailed work orders with issue descriptions",
        "Status tracking: Open, In Progress, Fixed, Deferred",
        "Technician assignment and responsibility tracking",
        "Cost tracking and budget management"
    ]
    
    for feature in maintenance_features:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    story.append(Paragraph("🆕 Timestamped Work Logging", heading3_style))
    work_logging_text = """
    The revolutionary work logging system creates individual timestamped entries for each work session, 
    providing a complete audit trail of all maintenance activities. This replaces traditional 
    note-overwriting with professional work documentation.
    """
    story.append(Paragraph(work_logging_text, body_style))
    
    work_logging_features = [
        "<b>Individual Work Entries:</b> Each update creates a new timestamped log entry",
        "<b>Session Tracking:</b> Record time spent, parts used, and costs per work session", 
        "<b>Technician Attribution:</b> Every entry is tied to the user who performed the work",
        "<b>Visual Timeline:</b> Chronological display with color-coded information",
        "<b>Complete Audit Trail:</b> Full history of who did what work and when"
    ]
    
    for feature in work_logging_features:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    # Reporting
    story.append(Paragraph("2.3 Reporting & Analytics", heading2_style))
    reporting_features = [
        "<b>Time-filtered Reports:</b> View data for 7, 30, 90 days, or full year",
        "<b>PDF Reports with Work Logs:</b> Professional reports including detailed work history",
        "<b>CSV Export:</b> Export game data for external analysis",
        "<b>Performance Analytics:</b> Top/worst performing games with charts",
        "<b>Cost Analysis:</b> Maintenance cost tracking and budgeting"
    ]
    
    for feature in reporting_features:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 3: User Roles & Permissions
    story.append(Paragraph("3. User Roles & Permissions", heading1_style))
    
    role_intro = """
    Arcade Tracker implements a hierarchical role-based access control system with four user levels. 
    Each higher level inherits all permissions from lower levels.
    """
    story.append(Paragraph(role_intro, body_style))
    
    # Roles table - split into two tables to prevent overflow
    story.append(Paragraph("Role Levels and Permissions", heading3_style))
    
    # Basic roles table
    roles_basic_data = [
        ["Role", "Level", "Key Permissions"],
        ["Read Only", "1", "View data, basic dashboard access"],
        ["Operator", "2", "Log work entries, create maintenance requests"],
        ["Manager", "3", "Manage work orders, record plays, generate reports"],
        ["Admin", "4", "User management, system administration, backups"]
    ]
    
    roles_table = Table(roles_basic_data, colWidths=[1.3*inch, 0.7*inch, 4*inch])
    roles_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('WORDWRAP', (0, 0), (-1, -1), True)
    ]))
    story.append(roles_table)
    
    story.append(Spacer(1, 12))
    
    # Use cases for each role
    story.append(Paragraph("Primary Use Cases", heading3_style))
    use_cases = [
        "<b>Read Only:</b> Customers, visitors, limited access users",
        "<b>Operator:</b> Technicians, maintenance staff, field workers", 
        "<b>Manager:</b> Supervisors, operations managers, business analysts",
        "<b>Admin:</b> System administrators, business owners, IT staff"
    ]
    
    for case in use_cases:
        story.append(Paragraph(f"• {case}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 4: Work Logging System
    story.append(Paragraph("4. Work Logging System", heading1_style))
    
    work_system_intro = """
    The work logging system is the cornerstone feature that transforms traditional maintenance 
    note-taking into professional work documentation with complete audit trails.
    """
    story.append(Paragraph(work_system_intro, body_style))
    
    story.append(Paragraph("4.1 How It Works", heading2_style))
    how_it_works = """
    Instead of overwriting maintenance notes, each work session creates a new timestamped entry. 
    This provides a complete chronological record of all work performed on each machine.
    """
    story.append(Paragraph(how_it_works, body_style))
    
    story.append(Paragraph("4.2 Work Entry Components", heading2_style))
    work_components = [
        "<b>Timestamp:</b> Automatically recorded when work is logged",
        "<b>User Attribution:</b> Links work to the technician who performed it",
        "<b>Work Description:</b> Detailed notes about what was accomplished",
        "<b>Time Spent:</b> Hours worked during this specific session",
        "<b>Parts Used:</b> Materials and components consumed",
        "<b>Session Cost:</b> Cost incurred during this work session",
        "<b>Status Updates:</b> Changes to overall work order status"
    ]
    
    for component in work_components:
        story.append(Paragraph(f"• {component}", bullet_style))
    
    story.append(Paragraph("4.3 Visual Timeline Interface", heading2_style))
    timeline_text = """
    Work entries are displayed in a professional timeline format with color-coded information 
    badges. Each entry shows the technician, time, costs, and detailed work performed, creating 
    a comprehensive visual history of all maintenance activities.
    """
    story.append(Paragraph(timeline_text, body_style))
    
    story.append(PageBreak())
    
    # Section 5: Workflows & Procedures
    story.append(Paragraph("5. Workflows & Procedures", heading1_style))
    
    story.append(Paragraph("5.1 Technician Workflow", heading2_style))
    tech_steps = [
        "Access maintenance order via 'View' or 'Update' button",
        "Review work history and current status",
        "Perform maintenance work on the machine",
        "Log work session details:",
        "  - Describe work performed in detail",
        "  - List parts/materials used",
        "  - Record time spent (e.g., 2.5 hours)",
        "  - Enter costs for this session",
        "Click 'Log Work Entry' to save",
        "New timestamped entry is added to work history"
    ]
    
    for i, step in enumerate(tech_steps, 1):
        if step.startswith("  "):
            story.append(Paragraph(f"    {step[2:]}", bullet_style))
        else:
            story.append(Paragraph(f"{i}. {step}", bullet_style))
    
    story.append(Paragraph("5.2 Manager Workflow", heading2_style))
    manager_steps = [
        "View complete work history via 'View' button",
        "Review chronological timeline of all work",
        "Analyze time and cost data across sessions",
        "Update overall work order status if needed",
        "Generate reports with work summaries",
        "Export detailed documentation for records"
    ]
    
    for i, step in enumerate(manager_steps, 1):
        story.append(Paragraph(f"{i}. {step}", bullet_style))
    
    story.append(Paragraph("5.3 Game Management Workflow", heading2_style))
    game_workflow = [
        "Add new games with detailed information",
        "Upload cabinet photos for identification", 
        "Set location and status information",
        "Record play data from coin counters",
        "Monitor performance analytics",
        "Create maintenance requests when needed"
    ]
    
    for i, step in enumerate(game_workflow, 1):
        story.append(Paragraph(f"{i}. {step}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 6: Reporting & Analytics
    story.append(Paragraph("6. Reporting & Analytics", heading1_style))
    
    reporting_intro = """
    Arcade Tracker provides comprehensive reporting capabilities with professional PDF exports 
    that include complete work history documentation.
    """
    story.append(Paragraph(reporting_intro, body_style))
    
    story.append(Paragraph("6.1 Maintenance Reports", heading2_style))
    maintenance_reports = [
        "<b>Time Filtering:</b> Select 7, 30, 90 days, or full year date ranges",
        "<b>Status Summaries:</b> Overview of open vs closed orders with statistics",
        "<b>Cost Analysis:</b> Total maintenance costs and average resolution times",
        "<b>Work Summaries:</b> Recent work performed on each order",
        "<b>PDF Export:</b> Professional formatting with work log details"
    ]
    
    for feature in maintenance_reports:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    story.append(Paragraph("6.2 Performance Analytics", heading2_style))
    performance_features = [
        "Top and worst performing games by daily revenue",
        "Play count trends and revenue analysis",
        "Game status distribution charts",
        "Location-based performance metrics"
    ]
    
    for feature in performance_features:
        story.append(Paragraph(f"• {feature}", bullet_style))
    
    story.append(Paragraph("6.3 PDF Export Improvements", heading2_style))
    pdf_improvements = [
        "✅ Fixed text cutoff issues with proper column sizing",
        "✅ Work history integration in reports", 
        "✅ Professional formatting and layout",
        "✅ Detailed work log sections with timestamps",
        "✅ Optimized fonts and spacing"
    ]
    
    for improvement in pdf_improvements:
        story.append(Paragraph(f"• {improvement}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 7: Technical Architecture  
    story.append(Paragraph("7. Technical Architecture", heading1_style))
    
    # Database Schema
    story.append(Paragraph("7.1 Database Schema", heading2_style))
    schema_data = [
        ["Table", "Purpose", "Key Fields"],
        ["games", "Game inventory", "name, location, status"],
        ["play_records", "Revenue tracking", "coin_count, plays_count"],
        ["maintenance_records", "Work orders", "issue, status, cost"],
        ["work_logs", "🆕 Work entries", "timestamp, user, description"],
        ["users", "Authentication", "username, role"]
    ]
    
    schema_table = Table(schema_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
    schema_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(schema_table)
    
    story.append(Spacer(1, 12))
    
    # Detailed table descriptions
    story.append(Paragraph("Table Details", heading3_style))
    table_details = [
        "<b>games:</b> Core game inventory with manufacturer, year, genre, location, status, and revenue data",
        "<b>play_records:</b> Individual play tracking entries with coin counts, calculated plays, and revenue per session",
        "<b>maintenance_records:</b> Work order management with issue descriptions, technician assignments, and costs",
        "<b>work_logs:</b> 🆕 Individual timestamped work entries with user attribution, time spent, and parts used",
        "<b>users:</b> User authentication and role management with hierarchical permission system"
    ]
    
    for detail in table_details:
        story.append(Paragraph(f"• {detail}", bullet_style))
    
    story.append(Paragraph("7.2 Technology Stack", heading2_style))
    tech_stack = [
        "<b>Backend Framework:</b> Flask with SQLAlchemy ORM",
        "<b>Database:</b> SQLite for local storage",
        "<b>Authentication:</b> Flask-Login with session management", 
        "<b>Security:</b> Flask-WTF with CSRF protection",
        "<b>PDF Generation:</b> ReportLab for professional reports",
        "<b>Frontend:</b> Jinja2 templates with custom CSS",
        "<b>Charts:</b> Chart.js for analytics visualization"
    ]
    
    for tech in tech_stack:
        story.append(Paragraph(f"• {tech}", bullet_style))
    
    story.append(PageBreak())
    
    # Section 8: Getting Started
    story.append(Paragraph("8. Getting Started", heading1_style))
    
    story.append(Paragraph("8.1 Installation", heading2_style))
    installation_steps = [
        "Ensure Python 3.8+ is installed",
        "Download or clone the Arcade Tracker files",
        "Install dependencies: pip install -r requirements.txt",
        "Run the application: python app.py",
        "Navigate to http://localhost:5000 in your browser"
    ]
    
    for i, step in enumerate(installation_steps, 1):
        story.append(Paragraph(f"{i}. {step}", bullet_style))
    
    story.append(Paragraph("8.2 Initial Setup", heading2_style))
    setup_steps = [
        "Complete the initial admin user setup",
        "Create additional user accounts for staff",
        "Add your arcade games to the inventory",
        "Set up game locations and initial status",
        "Begin tracking plays and maintenance activities"
    ]
    
    for i, step in enumerate(setup_steps, 1):
        story.append(Paragraph(f"{i}. {step}", bullet_style))
    
    story.append(Paragraph("8.3 Database Migration (Upgrading Users)", heading2_style))
    migration_text = """
    If upgrading from an older version, run the database migration script to add the new 
    WorkLog table for timestamped work entries:
    """
    story.append(Paragraph(migration_text, body_style))
    story.append(Paragraph("python create_work_log_table.py", styles['Code']))
    
    story.append(PageBreak())
    
    # Section 9: Troubleshooting
    story.append(Paragraph("9. Troubleshooting", heading1_style))
    
    troubleshooting = [
        ("<b>Port 5000 already in use:</b>", "Change the port in app.py or stop the conflicting service"),
        ("<b>CSRF token errors:</b>", "Ensure cookies are enabled and try refreshing the page"),
        ("<b>Work logs not appearing:</b>", "Run the database migration script for new installations"),
        ("<b>PDF reports cut off:</b>", "This has been fixed in v2.0 with proper column sizing"),
        ("<b>Permission denied errors:</b>", "Check user role assignments in the user management panel"),
        ("<b>Database errors:</b>", "Backup your data and recreate the database if corruption occurs")
    ]
    
    for issue, solution in troubleshooting:
        story.append(Paragraph(f"• {issue} {solution}", bullet_style))
    
    # Footer
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("🎮 Arcade Tracker v2.0 - Professional Arcade Management System 🔧", 
                          styles['Heading2']))
    
    # Build PDF
    doc.build(story)
    print(f"✅ Documentation generated: {filename}")
    print(f"📄 {len(story)} sections created with comprehensive coverage")
    return filename

if __name__ == '__main__':
    try:
        filename = create_documentation()
        print(f"\n🚀 Success! PDF documentation created: {filename}")
        print("📋 The documentation includes:")
        print("   • Complete feature overview")
        print("   • User roles and permissions") 
        print("   • Work logging system details")
        print("   • Workflows and procedures")
        print("   • Technical architecture")
        print("   • Installation and setup guide")
    except Exception as e:
        print(f"❌ Error generating documentation: {e}")
        sys.exit(1)