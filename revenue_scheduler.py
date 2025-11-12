#!/usr/bin/env python3
"""
Revenue scheduler for automatic daily syncing of skeeball revenue.

This module provides functionality to automatically sync skeeball lane
revenue to the arcade tracker database at midnight each day.
"""

import threading
import time
from datetime import datetime, time as dt_time
import logging

logger = logging.getLogger(__name__)


class RevenueScheduler:
    """Scheduler for automatic daily revenue syncing."""
    
    def __init__(self, app, lane_manager):
        """
        Initialize the revenue scheduler.
        
        Args:
            app: Flask application instance (for database context)
            lane_manager: LaneManager instance to access lanes
        """
        self.app = app
        self.lane_manager = lane_manager
        self.running = False
        self.thread = None
        self.sync_time = dt_time(0, 0)  # Midnight by default
    
    def start(self, sync_time=None):
        """
        Start the revenue scheduler.
        
        Args:
            sync_time: datetime.time object for when to sync (default: midnight)
        """
        if self.running:
            logger.warning("Revenue scheduler already running")
            return
        
        if sync_time:
            self.sync_time = sync_time
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f"✅ Revenue scheduler started (sync time: {self.sync_time})")
    
    def stop(self):
        """Stop the revenue scheduler."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Revenue scheduler stopped")
    
    def _run(self):
        """Main scheduler loop."""
        last_sync_date = None
        
        while self.running:
            try:
                now = datetime.now()
                current_date = now.date()
                current_time = now.time()
                
                # Check if it's time to sync and we haven't synced today yet
                if current_time >= self.sync_time and last_sync_date != current_date:
                    logger.info(f"Starting automatic revenue sync at {now}")
                    self._sync_all_lanes()
                    last_sync_date = current_date
                
                # Sleep for 60 seconds before checking again
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in revenue scheduler: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _sync_all_lanes(self):
        """Sync revenue for all registered lanes."""
        with self.app.app_context():
            from app import db, Game, PlayRecord
            from datetime import date
            
            lanes = self.lane_manager.get_all_lanes()
            synced_count = 0
            
            for lane_id, lane in lanes.items():
                try:
                    # Skip if not linked to game or no coins to sync
                    if not lane.game_db_id or lane.daily_coins == 0:
                        continue
                    
                    game = Game.query.get(lane.game_db_id)
                    if not game:
                        logger.warning(f"Lane {lane_id} linked to non-existent game {lane.game_db_id}")
                        continue
                    
                    # Calculate plays and revenue
                    plays = lane.daily_coins
                    revenue = plays * game.coins_per_play
                    
                    # Create play record
                    play_record = PlayRecord(
                        game_id=game.id,
                        coin_count=lane.stats["total_coins"],
                        plays_count=plays,
                        revenue=revenue,
                        date_recorded=date.today(),
                        notes=f'Auto-synced from {lane_id} at midnight'
                    )
                    
                    # Update game totals
                    game.total_plays += plays
                    game.total_revenue += revenue
                    
                    db.session.add(play_record)
                    db.session.commit()
                    
                    # Reset daily counter
                    lane.reset_daily_coins()
                    
                    synced_count += 1
                    logger.info(f"Synced {lane_id}: {plays} plays, ${revenue:.2f} revenue")
                    
                except Exception as e:
                    logger.error(f"Failed to sync lane {lane_id}: {e}")
                    db.session.rollback()
            
            if synced_count > 0:
                logger.info(f"✅ Revenue sync complete: {synced_count} lanes synced")
            else:
                logger.info("No lanes with revenue to sync")
    
    def force_sync(self):
        """Force an immediate sync of all lanes (for testing/manual trigger)."""
        logger.info("Force syncing all lanes...")
        self._sync_all_lanes()


def init_revenue_scheduler(app, lane_manager):
    """
    Initialize and start the revenue scheduler.
    
    Args:
        app: Flask application instance
        lane_manager: LaneManager instance
        
    Returns:
        RevenueScheduler instance
    """
    scheduler = RevenueScheduler(app, lane_manager)
    scheduler.start()
    return scheduler
