#!/usr/bin/env python3
"""
Create all required database tables directly with SQL
"""
import sqlite3
import os
from datetime import datetime

def backup_database():
    """Create a backup of the current database"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = 'backups'
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    source_db = 'arcade.db'
    backup_path = os.path.join(backup_dir, f"arcade_backup_before_create_{timestamp}.db")
    
    if os.path.exists(source_db):
        try:
            source_conn = sqlite3.connect(source_db)
            backup_conn = sqlite3.connect(backup_path)
            source_conn.backup(backup_conn)
            source_conn.close()
            backup_conn.close()
            print(f"✅ Backup created: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"❌ Failed to create backup: {e}")
            return None
    return None

def create_all_tables():
    """Create all required tables"""
    print("🔄 Creating database tables...")
    
    # Create backup first
    backup_path = backup_database()
    
    conn = sqlite3.connect('arcade.db')
    cursor = conn.cursor()
    
    try:
        # Game table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS game (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                manufacturer VARCHAR(50),
                year INTEGER,
                genre VARCHAR(50),
                location VARCHAR(20) DEFAULT 'Warehouse',
                floor_position VARCHAR(50),
                warehouse_section VARCHAR(50),
                status VARCHAR(20) DEFAULT 'Working',
                coins_per_play REAL DEFAULT 0.25,
                total_plays INTEGER DEFAULT 0,
                total_revenue REAL DEFAULT 0.0,
                counter_status VARCHAR(20) DEFAULT 'Working',
                counter_notes TEXT,
                date_added DATETIME,
                notes TEXT,
                image_filename VARCHAR(255),
                times_in_top_5 INTEGER DEFAULT 0,
                times_in_top_10 INTEGER DEFAULT 0
            )
        ''')
        print("✅ Game table created")
        
        # Play Record table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS play_record (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                game_id INTEGER NOT NULL,
                coin_count INTEGER NOT NULL DEFAULT 0,
                plays_count INTEGER NOT NULL DEFAULT 0,
                revenue REAL NOT NULL DEFAULT 0.0,
                date_recorded DATE NOT NULL,
                notes TEXT,
                FOREIGN KEY (game_id) REFERENCES game(id)
            )
        ''')
        print("✅ Play Record table created")
        
        # Maintenance Record table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS maintenance_record (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                game_id INTEGER NOT NULL,
                issue_description TEXT NOT NULL,
                fix_description TEXT,
                work_notes TEXT,
                parts_used TEXT,
                cost REAL,
                date_reported DATETIME,
                date_fixed DATETIME,
                status VARCHAR(20) DEFAULT 'Open',
                technician VARCHAR(50),
                photos TEXT,
                FOREIGN KEY (game_id) REFERENCES game(id)
            )
        ''')
        print("✅ Maintenance Record table created")
        
        # Work Log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS work_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                maintenance_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                work_description TEXT NOT NULL,
                parts_used TEXT,
                time_spent REAL,
                cost_incurred REAL,
                timestamp DATETIME,
                FOREIGN KEY (maintenance_id) REFERENCES maintenance_record(id),
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        print("✅ Work Log table created")
        
        # Inventory Item table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory_item (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(200) NOT NULL,
                description TEXT,
                stock_quantity INTEGER DEFAULT 0,
                unit_price REAL DEFAULT 0.0,
                minimum_stock INTEGER DEFAULT 5,
                supplier VARCHAR(200),
                part_number VARCHAR(100),
                date_added DATETIME,
                last_restocked DATETIME,
                notes TEXT
            )
        ''')
        print("✅ Inventory Item table created")
        
        # Item Game Compatibility table (association table)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS item_game_compatibility (
                item_id INTEGER NOT NULL,
                game_id INTEGER NOT NULL,
                PRIMARY KEY (item_id, game_id),
                FOREIGN KEY (item_id) REFERENCES inventory_item(id),
                FOREIGN KEY (game_id) REFERENCES game(id)
            )
        ''')
        print("✅ Item Game Compatibility table created")
        
        # Stock History table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS stock_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                change_type VARCHAR(20) NOT NULL,
                quantity_change INTEGER NOT NULL,
                previous_quantity INTEGER NOT NULL,
                new_quantity INTEGER NOT NULL,
                reason VARCHAR(200),
                timestamp DATETIME,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (item_id) REFERENCES inventory_item(id),
                FOREIGN KEY (user_id) REFERENCES user(id)
            )
        ''')
        print("✅ Stock History table created")
        
        # Low Stock Alert table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS low_stock_alert (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL,
                alert_triggered DATETIME,
                email_sent BOOLEAN DEFAULT 0,
                resolved BOOLEAN DEFAULT 0,
                resolved_date DATETIME,
                FOREIGN KEY (item_id) REFERENCES inventory_item(id)
            )
        ''')
        print("✅ Low Stock Alert table created")
        
        # Maintenance Inventory Usage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS maintenance_inventory_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                maintenance_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                quantity_used INTEGER NOT NULL,
                unit_price_at_time REAL NOT NULL,
                total_cost REAL NOT NULL,
                timestamp DATETIME,
                FOREIGN KEY (maintenance_id) REFERENCES maintenance_record(id),
                FOREIGN KEY (item_id) REFERENCES inventory_item(id)
            )
        ''')
        print("✅ Maintenance Inventory Usage table created")
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_game_location ON game(location)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_game_status ON game(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_play_record_date ON play_record(date_recorded)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_status ON maintenance_record(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_maintenance_date ON maintenance_record(date_reported)')
        print("✅ Indexes created")
        
        conn.commit()
        conn.close()
        
        print("🎉 All tables created successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create tables: {e}")
        conn.rollback()
        conn.close()
        return False

if __name__ == '__main__':
    success = create_all_tables()
    if not success:
        print("Table creation failed!")
        exit(1)