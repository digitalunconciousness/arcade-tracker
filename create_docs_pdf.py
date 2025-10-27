#!/usr/bin/env python3
"""Convert Arcade Tracker documentation to PDF"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER
import re
import os

def create_pdf_documentation():
    # Read the markdown file
    with open('ARCADE_TRACKER_DOCS.md', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        "ARCADE_TRACKER_DOCUMENTATION.pdf",
        pagesize=letter,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch,
        leftMargin=0.75*inch,
        rightMargin=0.75*inch
    )
    
    # Get default styles and create custom ones
    styles = getSampleStyleSheet()
    
    # Custom styles for better formatting
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        spaceAfter=30,
        textColor=colors.darkblue,
        alignment=TA_CENTER
    )
    
    h1_style = ParagraphStyle(
        'CustomH1',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=20,
        spaceBefore=30,
        textColor=colors.darkblue,
        borderColor=colors.darkblue,
        borderWidth=1,
        borderPadding=5
    )
    
    h2_style = ParagraphStyle(
        'CustomH2',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=15,
        spaceBefore=20,
        textColor=colors.darkgreen
    )
    
    h3_style = ParagraphStyle(
        'CustomH3',
        parent=styles['Heading3'],
        fontSize=12,
        spaceAfter=10,
        spaceBefore=15,
        textColor=colors.darkred
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=10,
        backColor=colors.lightgrey,
        borderColor=colors.grey,
        borderWidth=1,
        borderPadding=5,
        fontName='Courier'
    )
    
    bullet_style = ParagraphStyle(
        'CustomBullet',
        parent=styles['Normal'],
        leftIndent=20,
        bulletIndent=10,
        spaceAfter=5
    )
    
    # Story to hold document content
    story = []
    
    # Process the markdown content
    lines = content.split('\n')
    in_code_block = False
    code_block_content = []
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines
        if not line:
            story.append(Spacer(1, 6))
            continue
        
        # Handle code blocks
        if line.startswith('```'):
            if in_code_block:
                # End code block
                code_text = '\n'.join(code_block_content)
                story.append(Paragraph(code_text, code_style))
                story.append(Spacer(1, 10))
                code_block_content = []
                in_code_block = False
            else:
                # Start code block
                in_code_block = True
            continue
        
        if in_code_block:
            code_block_content.append(line)
            continue
        
        # Skip horizontal rules
        if line.startswith('---'):
            story.append(Spacer(1, 20))
            continue
        
        # Handle headers
        if line.startswith('# '):
            text = line[2:].strip()
            # Remove emojis for PDF compatibility
            text = re.sub(r'[^\w\s-]', '', text)
            story.append(Paragraph(text, title_style))
            continue
        elif line.startswith('## '):
            text = line[3:].strip()
            text = re.sub(r'[^\w\s-]', '', text)
            story.append(Paragraph(text, h1_style))
            continue
        elif line.startswith('### '):
            text = line[4:].strip()
            text = re.sub(r'[^\w\s-]', '', text)
            story.append(Paragraph(text, h2_style))
            continue
        elif line.startswith('#### '):
            text = line[5:].strip()
            text = re.sub(r'[^\w\s-]', '', text)
            story.append(Paragraph(text, h3_style))
            continue
        
        # Handle bullet points
        if line.startswith('- ') or line.startswith('* '):
            text = line[2:].strip()
            # Clean up markdown formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)  # Bold
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)      # Italic
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)  # Code
            # Remove most emojis but keep some useful ones
            text = re.sub(r'[^\w\s\-\(\)\[\]:.,!?/\'\"<>=]', '', text)
            story.append(Paragraph(f"• {text}", bullet_style))
            continue
        
        # Handle numbered lists
        if re.match(r'^\d+\.', line):
            text = re.sub(r'^\d+\.\s*', '', line)
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            text = re.sub(r'[^\w\s\-\(\)\[\]:.,!?/\'\"<>=]', '', text)
            story.append(Paragraph(text, bullet_style))
            continue
        
        # Handle regular paragraphs
        if line and not line.startswith('#'):
            # Clean up markdown formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)  # Bold
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)      # Italic
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)  # Code
            # Remove emojis for PDF compatibility
            text = re.sub(r'[^\w\s\-\(\)\[\]:.,!?/\'\"<>=]', '', text)
            
            # Skip lines that are just formatting
            if text.strip() and not text.strip() in ['**', '*', '---']:
                story.append(Paragraph(text, styles['Normal']))
                story.append(Spacer(1, 6))
    
    # Build the PDF
    doc.build(story)
    print("✅ PDF documentation created: ARCADE_TRACKER_DOCUMENTATION.pdf")

if __name__ == '__main__':
    try:
        create_pdf_documentation()
        print("🎉 Documentation PDF successfully generated!")
        print("📄 File: ARCADE_TRACKER_DOCUMENTATION.pdf")
    except Exception as e:
        print(f"❌ Error creating PDF: {e}")
        print("💡 Make sure you have reportlab installed: pip install reportlab")