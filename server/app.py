#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')
        
        if not username or not password:
            return {'error': 'username and password are required'}, 422

        if User.query.filter_by(username=username).first():
            return {'error': 'Username already exist'}, 422
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, _password_hash= hashed_password, image_url=image_url, bio=bio)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id

        return {
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }, 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if not user_id:
            return{'error': 'Unauthorized'}, 401
       
        user = db.session.get(User,user_id)
        if not user:
            return{'error': 'User not found'}, 401

        return {
            "id": user.id,
            "username": user.username,
            "image_url": user.image_url,
            "bio": user.bio
        }, 200
    
    

class Login(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'error':'username and Password are required'}, 400
        user =User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id

            return{
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }

        else:
            return{'error':'invalid credentials'},401
    
    

class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session ['user_id']is not None:
            session.pop('user_id',)
            return '', 204
        else:
            return{'error': 'Unauthorized'}, 401
    

class RecipeIndex(Resource):
    def get(self):

        if 'user_id' not  in session:
            return {'error': 'Unauthorized'}, 401
            
        user_id = session['user_id']

        recipes = Recipe.query.filter_by(user_id=user_id).all()

        recipe_list = []  
        for recipe in recipes:
                recipe_list.append({
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': recipe.user.id,
                        'username': recipe.user.username,
                        'bio': recipe.user.bio,
                        'image_url': recipe.user.image_url
                    }
                })
        return recipe_list, 200
    

    def post(self):
        if "user_id" not in session:
            return {'error': 'Unauthorized'}, 401
        user_id = session['user_id']

        data = request.get_json()

        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or not isinstance(minutes_to_complete, int):
            return{'error': 'Title, instructions, and minutes_to_complete are required fields.'}, 400

        try:
            new_recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
            )

            db.session.add(new_recipe)
            db.session.commit()
        except ValueError as e:
            return {'error': str(e)}, 422

        
        
        return {
            "id": new_recipe.id,
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete,
            "user_id": new_recipe.user_id
        }, 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)