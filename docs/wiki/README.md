# The wiki's pages

Everything in this folder except this file is the project wiki. When a change to it reaches
`master`, `.github/workflows/wiki.yml` copies the folder to the wiki, replacing what was there. Edit
the pages here, through a pull request; an edit made on the wiki itself is overwritten by the next
run. The workflow can also be run by hand from the Actions tab.

- One page per file. The file name is the page name: `Work-Orders.md` is the "Work Orders" page.
- `_Sidebar.md` is the menu beside every page.
- Links between pages use the page name, as the wiki does: `[Inventory](Inventory)`. They work on
  the wiki, not when reading the files here.
- Images go in `images/` and are linked as `images/name.png`.
- Screenshots use invented data only. `tests/screenshots/take.py` captures every page from the
  synthetic arcade in `tests/characterization/seed.py`.
