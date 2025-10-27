#!/usr/bin/env python3
"""
Import games from CSV backup file into Arcade Tracker database
"""

import os
import sys
import csv
import argparse
from datetime import datetime

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, Game

def import_games_from_csv(csv_path, dry_run=False):
    """Import games from CSV file"""
    
    if not os.path.exists(csv_path):
        print(f"❌ CSV file not found: {csv_path}")
        return False
    
    games_imported = 0
    games_skipped = 0
    errors = []
    
    print(f"📊 Reading CSV file: {csv_path}")
    
    with app.app_context():
        try:
            with open(csv_path, 'r', encoding='utf-8') as file:
                csv_reader = csv.DictReader(file)
                
                print(f"CSV columns: {csv_reader.fieldnames}")
                print()
                
                if dry_run:
                    print("🧪 DRY RUN MODE - No changes will be made")
                    print()
                
                for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 since row 1 is headers
                    try:
                        # Extract data from CSV
                        name = row['Game Name'].strip()
                        manufacturer = row.get('Manufacturer', '').strip() or None
                        location = row.get('Location', 'Warehouse').strip()
                        status = row.get('Status', 'Working').strip()
                        
                        # Convert numeric fields
                        try:
                            total_plays = int(float(row.get('Total Plays', 0)))
                            total_revenue = float(row.get('Total Revenue', 0.0))
                            times_in_top_5 = int(float(row.get('Top 5 Count', 0)))
                            times_in_top_10 = int(float(row.get('Top 10 Count', 0)))
                        except (ValueError, TypeError):
                            total_plays = 0
                            total_revenue = 0.0
                            times_in_top_5 = 0
                            times_in_top_10 = 0
                        
                        if not name:
                            print(f"⚠️  Row {row_num}: Skipping game with empty name")
                            games_skipped += 1
                            continue
                        
                        # Check if game already exists
                        existing_game = Game.query.filter_by(name=name).first()
                        if existing_game:
                            print(f"⚠️  Row {row_num}: Game '{name}' already exists, skipping")
                            games_skipped += 1
                            continue
                        
                        if not dry_run:
                            # Create new game
                            game = Game(
                                name=name,
                                manufacturer=manufacturer,
                                location=location,
                                status=status,
                                total_plays=total_plays,
                                total_revenue=total_revenue,
                                coins_per_play=0.25,  # Default
                                times_in_top_5=times_in_top_5,
                                times_in_top_10=times_in_top_10,
                                date_added=datetime.now()
                            )
                            
                            db.session.add(game)
                            print(f"✅ Row {row_num}: Added '{name}' ({location}, {status})")
                        else:
                            print(f"📝 Row {row_num}: Would add '{name}' ({location}, {status})")
                        
                        games_imported += 1
                        
                    except Exception as e:
                        error_msg = f"Row {row_num}: Error processing '{row.get('Game Name', 'Unknown')}': {str(e)}"
                        errors.append(error_msg)
                        print(f"❌ {error_msg}")
                
                if not dry_run and games_imported > 0:
                    db.session.commit()
                    print(f"\n💾 Database changes committed")
                elif dry_run:
                    print(f"\n🧪 Dry run completed - no changes made")
        
        except Exception as e:
            if not dry_run:
                db.session.rollback()
            print(f"❌ Error reading CSV file: {e}")
            return False
    
    # Summary
    print(f"\n📊 Import Summary:")
    print(f"   Games imported: {games_imported}")
    print(f"   Games skipped: {games_skipped}")
    print(f"   Errors: {len(errors)}")
    
    if errors:
        print(f"\n❌ Errors encountered:")
        for error in errors:
            print(f"   - {error}")
    
    return len(errors) == 0

def show_current_games():
    """Show current games in database"""
    with app.app_context():
        games = Game.query.all()
        print(f"\n📊 Current database contains {len(games)} games:")
        if games:
            for game in games:
                print(f"   - {game.name} ({game.location}, {game.status})")
        else:
            print("   (No games found)")

def main():
    parser = argparse.ArgumentParser(description='Import games from CSV backup into Arcade Tracker')
    parser.add_argument('csv_file', help='Path to CSV backup file')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be imported without making changes')
    parser.add_argument('--show-current', action='store_true', help='Show current games in database before import')
    
    args = parser.parse_args()
    
    # Change to project directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    os.chdir(parent_dir)
    
    print("🎮 Arcade Tracker CSV Import Tool")
    print("=" * 40)
    
    if args.show_current:
        show_current_games()
        print()
    
    # Create backup before import
    if not args.dry_run:
        print("🔄 Creating backup before import...")
        try:
            import subprocess
            result = subprocess.run([sys.executable, 'scripts/backup_database.py', 'backup'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Backup created successfully")
            else:
                print(f"⚠️  Backup failed: {result.stderr}")
                response = input("Continue without backup? (y/N): ")
                if response.lower() != 'y':
                    print("Import cancelled")
                    return
        except Exception as e:
            print(f"⚠️  Could not create backup: {e}")
            response = input("Continue without backup? (y/N): ")
            if response.lower() != 'y':
                print("Import cancelled")
                return
    
    # Perform import
    success = import_games_from_csv(args.csv_file, args.dry_run)
    
    if success:
        if args.dry_run:
            print(f"\n🧪 Dry run completed successfully!")
            print(f"Run without --dry-run to actually import the data.")
        else:
            print(f"\n🎉 Import completed successfully!")
            print(f"Your arcade game data has been restored from the CSV backup.")
            show_current_games()
    else:
        print(f"\n❌ Import failed. Please check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main() or 0)