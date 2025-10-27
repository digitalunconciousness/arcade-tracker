from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, filename):
    # Create image with dark background
    img = Image.new('RGB', (size, size), color='#0f0f23')
    draw = ImageDraw.Draw(img)
    
    # Draw a neon cyan circle
    margin = size // 8
    draw.ellipse([margin, margin, size-margin, size-margin], 
                 fill='#00d9ff', outline='#9d00ff', width=size//20)
    
    # Draw joystick emoji or text
    font_size = size // 2
    try:
        # Try to use a nice font
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
    except:
        font = ImageFont.load_default()
    
    text = "🎮"
    # Get text size
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    # Center the text
    x = (size - text_width) // 2
    y = (size - text_height) // 2
    
    draw.text((x, y), text, fill='#000000', font=font)
    
    # Save
    os.makedirs('static', exist_ok=True)
    img.save(f'static/{filename}')
    print(f"Created {filename}")

# Generate icons
create_icon(192, 'icon-192.png')
create_icon(512, 'icon-512.png')
print("Icons generated successfully!")