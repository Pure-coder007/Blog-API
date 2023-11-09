import mysql.connector
from datetime import datetime
from mysql.connector import Error
from database import config


class User():
    def __init__(self, id, first_name, last_name, email, password, is_admin=False):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.is_admin = is_admin

        @classmethod
        def get(cls, user_id):
            pass



def add_user(first_name, last_name, email, password, is_admin=False):
    try:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        cursor.execute("INSERT INTO user(first_name, last_name, email, password, is_admin) VALUES (%s, %s, %s, %s, %s)", (first_name, last_name, email, password, is_admin))
        connection.commit()
    except mysql.connection.Error as err:
        print('Error: ', err)
    finally:
        cursor.close()
        connection.close()



# Getting user by email
def get_user(email):
    connection = None
    cursor = None
    try:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute('SELECT * FROM user WHERE email=%s', (email,))

        user_record = cursor.fetchone()
        
        if user_record:
            return User(
                id=user_record['id'],
                first_name=user_record['first_name'],
                last_name=user_record['last_name'],
                email=user_record['email'],
                password=user_record['password'],
                is_admin=user_record['is_admin']
            )
        return None
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None
    finally:
        if cursor: cursor.close()
        if connection: connection.close()



def get_user_by_id(user_id):
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM user WHERE id=%s', (user_id,))
    user_record = cursor.fetchone()
    cursor.close()
    connection.close()

    if user_record:
        return User(id=user_record['id'], first_name=user_record['first_name'], last_name=user_record['last_name'], email=user_record['email'], password=user_record['password'], is_admin=user_record['is_admin'])
    return None




        
def get_post_by_id(post_id):
    try:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor(dictionary=True)
        query = "SELECT * FROM posts WHERE id = %s"
        cursor.execute(query, (post_id,))
        
        # Fetch the result (assuming you want a single post)
        post = cursor.fetchone()
        
        if post:
            return post
        else:
            return None

    except Error as e:
        print(f"Error: {e}")
        return None

    finally:
        # Close the cursor and connection when you're done
        cursor.close()
        connection.close()