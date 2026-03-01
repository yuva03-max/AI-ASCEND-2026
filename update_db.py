import sqlite3
import os

db_path = 'data.sqlite'

if os.path.exists(db_path):
    print(f"Updating database at {db_path}...")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        


        # Add google_drive_credentials
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN google_drive_credentials TEXT")
            print("Added column: google_drive_credentials")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column google_drive_credentials already exists.")
            else:
                print(f"Error adding google_drive_credentials: {e}")

        # Add google_drive_folder_id
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN google_drive_folder_id VARCHAR(100)")
            print("Added column: google_drive_folder_id")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column google_drive_folder_id already exists.")
            else:
                print(f"Error adding google_drive_folder_id: {e}")

        # Add google_drive_file_id to Note
        try:
            cursor.execute("ALTER TABLE note ADD COLUMN google_drive_file_id VARCHAR(100)")
            print("Added column: google_drive_file_id to Note")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column google_drive_file_id already exists in Note.")
            else:
                print(f"Error adding google_drive_file_id to Note: {e}")

        # Add google_drive_web_link to Note
        try:
            cursor.execute("ALTER TABLE note ADD COLUMN google_drive_web_link TEXT")
            print("Added column: google_drive_web_link to Note")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column google_drive_web_link already exists in Note.")
            else:
                print(f"Error adding google_drive_web_link to Note: {e}")


        # Add password_changed_at
        try:
            cursor.execute("ALTER TABLE user ADD COLUMN password_changed_at DATETIME")
            print("Added column: password_changed_at")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print("Column password_changed_at already exists.")
            else:
                print(f"Error adding password_changed_at: {e}")
        
        conn.commit()
        conn.close()
        print("Database update complete.")
    except Exception as e:
        print(f"Failed to update database: {e}")
else:
    print(f"Database file {db_path} not found. It will be created fresh with all columns.")
