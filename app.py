from flask import Flask, Blueprint, jsonify, request
import mysql.connector
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import random
from models import add_user, get_user, get_user_by_id
from database import config
from datetime import datetime


app = Flask(__name__)

bcrypt = Bcrypt(app)
jwt = JWTManager()
auth = Blueprint('auth', __name__)
app.config.from_pyfile('config.py')


# Create app
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.secret_key = 'language007'
    jwt.init_app(app)
    app.register_blueprint(auth, url_prefix='/auth/v1')
    return app

def email_exists(email):
    user = get_user(email)
    return user is not None


@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if request.method == 'POST':
        first_name = data['first_name']
        last_name = data['last_name']
        email = data['email']
        password = data['password']

        # Check if email is unique
        if email_exists(email):
            return jsonify({
                'message' : 'Email already exists',
                'status' : 400
            }), 400
        
        hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Always change to true if creating an admin
        add_user(first_name, last_name, email, hash_password, False)
        return jsonify ({
            'message' : 'User created successfully',
            'status' : 200
        }), 200
    


# Login route
@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({ 'message' : 'Missing JSON in request', 'status' : 400}), 400
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify ({'message': 'Missing email or password', 'status' : 400}), 400
    
    user = get_user(email)
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        print('Login Successful')
        print('Access_token: ', access_token)
        return jsonify ({
            'message' : 'Login Successful',
            'access_token' : access_token, 
            'status' : 200
        }), 200
    return jsonify({'message': 'Invalid username or password', 'staus': 400}), 400



# Creating posts
@auth.route('/post', methods=['POST'])
@jwt_required()
def post():
    user_id = get_jwt_identity() 
    print('userrrr:', user_id) # Retrieve the user's ID from the JWT
    if not user_id:
        return jsonify({'message': 'User not found'}), 404

    # Fetch the associated user information (including the author name) from the database
    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()

    query = "SELECT first_name FROM user WHERE id = %s"
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    print('usereeeeeeeee:', user)
    if not user:
        cursor.close()
        connection.close()
        return jsonify({'message': 'User not found in the database'}), 404

    author = user[0]  
    title = request.json.get('title')
    post = request.json.get('post')
    
    query = "INSERT INTO posts (user_id, author, title, post) VALUES (%s, %s, %s, %s)"
    cursor.execute(query, (user_id, author, title, post))
    print({'title:', title})
    print({'posttttt:', post})
    print({'author:', author})
    connection.commit()
    cursor.close()
    connection.close()
    return jsonify({'message': 'Post created successfully', 'status': 201}), 201


# Approve posts
@auth.route('/approve/<int:post_id>', methods=['POST'])
@jwt_required()
def approve(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "UPDATE posts SET approved = 1 WHERE id = %s"
            result = cursor.execute(query, (post_id,))
            connection.commit()
            cursor.close()
            connection.close()

            if result == 0:
                return jsonify({'message': f'Post with id {post_id} not found'}), 404
            else:
                return jsonify({'message': 'Post approved successfully', 'status': 200}), 200



# Show approved post to users
@auth.route('/view_posts', methods=['GET'])
@jwt_required()
def view_posts():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT * FROM posts WHERE approved = 1"
        cursor.execute(query)
        posts = cursor.fetchall()
        
        # Convert the list of posts to a list of dictionaries
        posts_list = []
        for post in posts:
            post_dict = {
                # 'post_id': post[0],
                'author': post[2],
                'title': post[3],
                'post': post[4],  # Leave 'date' as a string
                'date': post[5]
            }
            posts_list.append(post_dict)

        cursor.close()
        connection.close()
        return jsonify({'message': 'All posts', 'posts': posts_list, 'status': 200}), 200




# Get all posts (approved and unapproved by admin)
@auth.route('/all_posts', methods=['GET'])
@jwt_required()
def all_posts():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "SELECT * FROM posts"
            cursor.execute(query)
            posts = cursor.fetchall()
            
            # Convert the list of posts to a list of dictionaries
            posts_list = []
            for post in posts:
                post_dict = {
                    'post_id': post[0],
                    'author': post[1],
                    'title': post[2],
                    'post': post[3],
                    'date': post[4].strftime('%Y-%m-%d %H:%M:%S'),
                    'user_id': post[5]
                }
                posts_list.append(post_dict)

            cursor.close()
            connection.close()
            return jsonify({'message': 'All posts', 'posts': posts_list, 'status': 200}), 200



# Admin view single post
@auth.route('/single_post/<int:post_id>', methods=['GET'])
@jwt_required()
def single_post(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "SELECT * FROM posts WHERE id = %s"
            cursor.execute(query, (post_id,))
            post = cursor.fetchone()
            if not post:
                cursor.close()
                connection.close()
                return jsonify({'message': 'Post not found'}), 404
            else:
                post_dict = {
                    'post_id': post[0],
                    'author': post[1],
                    'title': post[2],
                    'post': post[3],
                    'date': post[4].strftime('%Y-%m-%d %H:%M:%S'),
                    'user_id': post[5]
                }
                cursor.close()
                connection.close()
                return jsonify({'message': 'Post found', 'post': post_dict, 'status': 200}), 200


# User update post
@auth.route('/update_post/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404

    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()

    # Check if the user is the author of the post
    query = "SELECT user_id FROM posts WHERE id = %s"
    cursor.execute(query, (post_id,))
    author_id = cursor.fetchone()
    if author_id and author_id[0] == user_id:
        title = request.json.get('title')
        post = request.json.get('post')

        if title is not None and post is not None:
            # Update the post if title and content are provided
            query = "UPDATE posts SET title = %s, post = %s WHERE id = %s"
            cursor.execute(query, (title, post, post_id))
            connection.commit()
            cursor.close()
            connection.close()
            return jsonify({'message': 'Post updated successfully', 'status': 200}), 200
        else:
            cursor.close()
            connection.close()
            return jsonify({'message': 'Title and post content must be provided for the update'}), 400

    cursor.close()
    connection.close()
    return jsonify({'message': 'User is not authorized to update this post'}, 401)



# Admin delete post
@auth.route('/delete_post/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "DELETE FROM posts WHERE id = %s"
            result = cursor.execute(query, (post_id,))
            connection.commit()
            cursor.close()
            connection.close()

            if result == 0:
                return jsonify({'message': f'Post with id {post_id} not found'}), 404
            else:
                return jsonify({'message': 'Post deleted successfully', 'status': 200}), 200



# User delete own post
@auth.route('/delete_own_post/<int:post_id>', methods=['DELETE'])
@jwt_required()
def delete_own_post(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404

    connection = mysql.connector.connect(**config)
    cursor = connection.cursor()

    # Check if the user is the author of the post
    query = "SELECT user_id, author, title, post FROM posts WHERE id = %s"
    cursor.execute(query, (post_id,))
    post_info = cursor.fetchone()
    if post_info and post_info[0] == user_id:
        # Insert the deleted post into the "deleted_posts" table
        insert_query = "INSERT INTO deleted_posts (author, title, user_id) VALUES (%s, %s, %s)"
        deleted_reason = "User-deleted"  # You can provide a reason for the deletion
        cursor.execute(insert_query, (post_info[1], post_info[2], user_id))

        # Delete the post from the "posts" table
        delete_query = "DELETE FROM posts WHERE id = %s"
        result = cursor.execute(delete_query, (post_id,))
        connection.commit()
        cursor.close()
        connection.close()

        if result == 0:
            return jsonify({'message': f'Post with id {post_id} not found'}), 404
        else:
            return jsonify({'message': 'Post deleted successfully', 'status': 200}), 200

    cursor.close()
    connection.close()
    return jsonify({'message': 'User is not authorized to delete this post'}, 401)



# Admin view deleted posts
@auth.route('/deleted_posts', methods=['GET'])
@jwt_required()
def deleted_posts():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "SELECT * FROM deleted_posts"
            cursor.execute(query)
            posts = cursor.fetchall()
            
            # Convert the list of posts to a list of dictionaries
            posts_list = []
            for post in posts:
                post_dict = {
                    # 'post_id': post[0],
                    # 'author': post[0],
                    'author': post[1],
                    'title': post[2],
                    'date': post[3]
                }
                posts_list.append(post_dict)

            cursor.close()
            connection.close()
            return jsonify({'message': 'All deleted posts', 'posts': posts_list, 'status': 200}), 200



# Admin delete user
@auth.route('/delete_user/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if not current_user_id:
        return jsonify({'message': 'User not found'}), 404
    else:
        connection = mysql.connector.connect(**config)
        cursor = connection.cursor()
        query = "SELECT is_admin FROM user WHERE id = %s"
        cursor.execute(query, (current_user_id,))
        user = cursor.fetchone()
        if not user:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User not found in the database'}), 404
        is_admin = user[0]
        if not is_admin:
            cursor.close()
            connection.close()
            return jsonify({'message': 'User is not an admin'}), 401
        else:
            query = "DELETE FROM user WHERE id = %s"
            result = cursor.execute(query, (user_id,))
            connection.commit()
            cursor.close()
            connection.close()

            if result == 0:
                return jsonify({'message': f'User with id {user_id} not found'}), 404
            else:
                return jsonify({'message': 'User deleted successfully', 'status': 200}), 200