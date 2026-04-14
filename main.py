import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

from gui.main_window import MainWindow


def load_theme(app, path="gui/dashboard.qss"):
    """
    Loads the global QSS theme for the entire application.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except Exception as e:
        print(f"[Theme] Failed to load QSS: {e}")

def main():
    app = QApplication(sys.argv)
    load_theme(app)
    
    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
