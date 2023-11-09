import mysql.connector
from datetime import datetime

config = {
    'user' : 'root',
    'password' : 'language007',
    'host' : 'localhost',
    'database' : 'blog_api'
}

def setup_database():
    config['database'] = None
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user(
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS posts(
        id INT AUTO_INCREMENT PRIMARY KEY,
        author VARCHAR(255) NOT NULL,
        title VARCHAR(255) NOT NULL,
        post TEXT NOT NULL,
        FOREIGN KEY (id) REFERENCES user(id),
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS deleted_posts(
        id INT AUTO_INCREMENT PRIMARY KEY,
        author VARCHAR(255) NOT NULL,
        title VARCHAR(255) NOT NULL,
        reason TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (id) REFERENCES user(id) ON DELETE CASCADE,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
""")