from __future__ import unicode_literals
from models import *
from django.contrib import messages
import re
import bcrypt
from django.shortcuts import render, redirect

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

def index(request):
    return render(request, 'user_dashboard/index.html')

def signin(request):
    return render(request, 'user_dashboard/signin.html')

def process_signin(request):
    if request.method == 'POST':
        error = False
        retrieved_user = User.objects.get(email=request.POST['email'])
        retrieved_password = retrieved_user.password

        if not bcrypt.checkpw(request.POST['password'].encode(), retrieved_password.encode()):
            messages.error(request, 'email/password incorrect')
            error = True

        if error == True:
            return redirect('/signin')

        request.session['user_id'] = retrieved_user.id

        if retrieved_user.admin:
            return redirect('/dashboard/admin')
        else:
            return redirect('/dashboard')
    else:
        return redirect('/signin')

def register(request):
    return render(request, 'user_dashboard/register.html')

def process_register(request):
    if request.method == 'POST':
        error = False
        
        if len(request.POST['first_name']) < 1 or len(request.POST['last_name']) < 1 or len(request.POST['email']) < 1 or len(request.POST['password']) < 1 or len(request.POST['confirm_password']) < 1:
            messages.error(request, "All fields are required")
            error = True  
        
        if len(request.POST['first_name']) < 2:
            messages.error(request, "First name is too short")
            error = True

        if len(request.POST['last_name']) < 2:
            messages.error(request, "Last name is too short")
            error = True

        if not request.POST['first_name'].isalpha() or not request.POST['last_name'].isalpha():
            messages.error(request, "Names must only contain letters")
            error = True

        if not re.match(EMAIL_REGEX, request.POST['email']):
            messages.error(request, "Must use a valid email address")
            error = True

        if len(User.objects.filter(email=request.POST['email'])):
            messages.error(request, "Email is already in use")
            error = True

        if len(request.POST['password']) < 8:
            messages.error(request, "Password must be longer than 8 characters")
            error = True

        if request.POST['confirm_password'] != request.POST['password']:
            messages.error(request, "Passwords don't match")
            error = True

        if error == True:
            return redirect('/register')
    
        else:     
            hashed_password = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())

            if len(User.objects.all()) < 1:
                admin = True
            else:
                admin = False

            new_user = User.objects.create(
                first_name = request.POST['first_name'],
                last_name = request.POST['last_name'],
                email = request.POST['email'],
                password = hashed_password,
                admin = admin
            )
            
            request.session['user_id'] = new_user.id
            
            if new_user.admin:
                return redirect('/dashboard/admin')
            else:
                return redirect('/dashboard')
        
    else:
        return redirect('/')

def admin_dashboard(request):
    try:
        request.session['user_id']
    except KeyError:
        return redirect('/') 

    context = {
        "user": User.objects.get(id=request.session['user_id']),
        "all_users": User.objects.all()
    }

    try:
        context['user'].admin
        return render(request, "user_dashboard/admin_dashboard.html", context)
    except:
        return redirect('/dashboard')

def new_user(request):
    try:
        request.session['user_id']
    except KeyError:
        return redirect('/') 

    try:
        User.objects.get(id=request.session['user_id']).admin
        return render(request, "user_dashboard/new_user.html")
    except:
        return redirect('/logout')

def add_user(request):
    try:
        request.session['user_id']
    except KeyError:
        return redirect('/') 

    if request.method == 'POST':
        error = False
    
    if len(request.POST['first_name']) < 1 or len(request.POST['last_name']) < 1 or len(request.POST['email']) < 1 or len(request.POST['password']) < 1 or len(request.POST['confirm_password']) < 1:
        messages.error(request, "All fields are required")
        error = True  
    
    if len(request.POST['first_name']) < 2:
        messages.error(request, "First name is too short")
        error = True

    if len(request.POST['last_name']) < 2:
        messages.error(request, "Last name is too short")
        error = True

    if not request.POST['first_name'].isalpha() or not request.POST['last_name'].isalpha():
        messages.error(request, "Names must only contain letters")
        error = True

    if not re.match(EMAIL_REGEX, request.POST['email']):
        messages.error(request, "Must use a valid email address")
        error = True

    if len(User.objects.filter(email=request.POST['email'])):
        messages.error(request, "Email is already in use")
        error = True

    if len(request.POST['password']) < 8:
        messages.error(request, "Password must be longer than 8 characters")
        error = True

    if request.POST['confirm_password'] != request.POST['password']:
        messages.error(request, "Passwords don't match")
        error = True

    if error == True:
        return redirect('/users/new')

    else:     
        hashed_password = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        admin = False

        new_user = User.objects.create(
            first_name = request.POST['first_name'],
            last_name = request.POST['last_name'],
            email = request.POST['email'],
            password = hashed_password,
            admin = admin
        )
        
        messages.success(request, "User was created successfully")

        return redirect('/users/new')

def user_dashboard(request):
    try:
        request.session['user_id']
    except KeyError:
        return redirect('/')

    context = {
        "user": User.objects.get(id=request.session['user_id']),
        "all_users": User.objects.all()
    }

    try:
        context['user'].admin
        print context['user'].admin
        return redirect("/dashboard/admin")
    except:
        return render(request, 'user_dashboard/user_dashboard.html', context)

def show_user(request, user_id):
    try:
        request.session['user_id']
    except KeyError:
        return redirect('/')

    context = {
        "user": User.objects.get(id=user_id),
        
    }


    return render(request, "user_dashboard/show_user.html", context)

def logout(request):
    request.session.clear
    return redirect('/')

