# Branch Structure

This repository has two main branches to accommodate different deployment scenarios:

## master (Full Version)

**Branch:** `master`  
**Purpose:** Complete arcade tracker with all features

### Includes:
- Complete game and inventory management
- Maintenance tracking with work logs
- Revenue reporting and analytics
- User management and authentication
- Skeeball Integration
  - Raspberry Pi GPIO control
  - Multi-lane support with Pi Pico
  - Web-based control panel
  - Simulator and testing tools
  - Real-time scoring system

### Dependencies:
- All standard Flask/SQLAlchemy packages
- `gpiozero` - GPIO interface for Raspberry Pi
- `pyserial` - Serial communication for multi-lane setups

### Use Cases:
- Arcades with skeeball machines
- Raspberry Pi deployments
- Full hardware integration setups
- Multi-lane skeeball operations

### Installation:
```bash
git clone https://github.com/digitalunconciousness/arcade-tracker.git
cd arcade-tracker
pip install -r requirements.txt
python app.py
```

---

## no-skeeball (Core Version)

**Branch:** `no-skeeball`  
**Purpose:** Arcade tracker without skeeball hardware integration

### Includes:
- Complete game and inventory management
- Maintenance tracking with work logs
- Revenue reporting and analytics
- User management and authentication
- Monthly Top 5/Top 10 rankings
- Executive summary dashboard

### Excludes:
- Skeeball routes and templates
- GPIO hardware integration
- Pi Pico multi-lane support
- Skeeball-specific dependencies

### Dependencies:
- Flask and SQLAlchemy core packages
- No GPIO or serial communication libraries

### Use Cases:
- Non-Raspberry Pi deployments
- Arcades without skeeball machines
- Development on Windows/Mac/Linux
- Simplified installations
- Cloud deployments

### Installation:
```bash
git clone -b no-skeeball https://github.com/digitalunconciousness/arcade-tracker.git
cd arcade-tracker
pip install -r requirements.txt
python app.py
```

---

## Switching Between Branches

### Switch to Full Version (with skeeball):
```bash
git checkout master
pip install -r requirements.txt
```

### Switch to Core Version (without skeeball):
```bash
git checkout no-skeeball
pip install -r requirements.txt
```

---

## Branch Maintenance

### Updating the no-skeeball Branch

When adding new features to master that are NOT skeeball-related:

1. Commit changes to master
2. Switch to no-skeeball: `git checkout no-skeeball`
3. Cherry-pick the commit: `git cherry-pick <commit-hash>`
4. Push both branches:
   ```bash
   git push origin master
   git push origin no-skeeball
   ```

### Features to Keep Synchronized

Both branches should have:
- Core game management features
- Maintenance system updates
- Inventory management improvements
- Reporting enhancements
- Security updates
- Bug fixes

### Features Only in Master

Only master should have:
- Skeeball-related code
- GPIO integrations
- Pi Pico multi-lane support
- Hardware-specific features

---

## Which Branch Should I Use?

### Use `master` if:
- You have skeeball machines
- You're deploying on a Raspberry Pi
- You want GPIO hardware integration
- You need multi-lane skeeball support

### Use `no-skeeball` if:
- You don't have skeeball machines
- You're deploying on a standard server
- You want a simpler installation
- You're developing on Windows/Mac
- You want fewer dependencies

---

## Documentation

### Master Branch Documentation:
- README.md includes skeeball setup
- Wiki includes Skeeball Integration page
- `rpi_skeeball/` folder with hardware guides
- `DEPLOYMENT_CHECKLIST.md` with Pi setup

### No-Skeeball Branch Documentation:
- README.md focuses on core features
- Wiki excludes skeeball page
- No hardware-specific documentation
- Standard web application deployment

---

## Support

For issues specific to:
- **Skeeball integration**: Use master branch, check `SKEEBALL_TROUBLESHOOTING.md`
- **Core features**: Either branch, open an issue on GitHub
- **Hardware**: Master branch only, check hardware documentation

---

**Last Updated:** November 11, 2025  
**Repository:** https://github.com/digitalunconciousness/arcade-tracker
