# users/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.conf import settings
from .models import Profile, Affidavit
from .forms import ReviewForm,AffidavitForm
import uuid
from django.utils.html import escape
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.shortcuts import get_object_or_404
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils.encoding import force_str
from django.core.validators import validate_email
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.tokens import default_token_generator


def register(request):
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if password == password2:
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email is already taken')
            elif len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char.islower() for char in password) or not any(char.isupper() for char in password):
                messages.error(request, 'Password must be at least 8 characters long, contain both numbers and letters, and have both lowercase and uppercase letters')
            else:
                user = User.objects.create_user(username=email, email=email, password=password)
                user.save()
                verification_code = uuid.uuid4()
                profile = Profile(user=user, first_name=first_name, last_name=last_name, verification_code=verification_code)
                profile.save()
                send_verification_email(user, verification_code)
                messages.success(request, 'Registration successful. Please check your email to verify your account.')
                return redirect('verify')
        else:
            messages.error(request, 'Passwords do not match')

    return render(request, 'register.html')




def send_verification_email(user, verification_code):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = str(verification_code)
    verification_link = reverse('verify_email', kwargs={'uidb64': uid, 'token': token})
    verification_url = f"{settings.SITE_URL}{verification_link}"

    subject = 'Verify your email address'
    message = f'Hi {user.username},\n\nPlease click the following link to verify your email address: {verification_url}\n\nThank you!'
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)



def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
        profile = Profile.objects.get(user=user)
        verification_code = uuid.UUID(token)
        
        if profile.verification_code == verification_code and not profile.email_verified:
            profile.email_verified = True
            profile.save()
            messages.success(request, 'Email verified successfully!')
            return redirect('login')
        else:
            messages.error(request, 'Verification link is invalid or has already been used.')
            return render(request, 'verify.html')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, Profile.DoesNotExist):
        messages.error(request, 'Verification link is invalid.')
        return render(request, 'verify.html')


def verify (request):
    return render (request, 'verify.html')


def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        # Validate email
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Invalid email format')
            return render(request, 'login.html')

        # Check if email and password are provided
        if not email or not password:
            messages.error(request, 'Email and password are required')
            return render(request, 'login.html')

        # Authenticate user
        user = authenticate(request, username=email, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('home')  # Adjust the redirect as needed
        else:
            messages.error(request, 'Invalid credentials')

    return render(request, 'login.html')




def password_reset_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        user = User.objects.filter(email=email).first()
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            password_reset_link = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            password_reset_url = f"{settings.SITE_URL}{password_reset_link}"

            subject = 'Reset your password'
            message = f'Hi {user.username},\n\nPlease click the following link to reset your password: {password_reset_url}\n\nThank you!'
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list)

            messages.success(request, 'A link to reset your password has been sent to your email.')
            return redirect('login')
        else:
            messages.error(request, 'This email is not registered.')
    return render(request, 'password_reset_form.html')



def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password')
            password2 = request.POST.get('password2')
            if password == password2:
                if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char.islower() for char in password) or not any(char.isupper() for char in password):
                    messages.error(request, 'Password must be at least 8 characters long, contain both numbers and letters, and have both lowercase and uppercase letters')
                else:
                    user.set_password(password)
                    user.save()
                    messages.success(request, 'Password has been reset successfully!')
                    return redirect('login')
            else:
                messages.error(request, 'Passwords do not match')
        return render(request, 'password_reset_confirm.html')
    else:
        messages.error(request, 'The reset link is invalid, possibly because it has already been used.')
        return redirect('password_reset_form')






@login_required
def home(request):
    user_profile = Profile.objects.get(user=request.user)
    completed_affidavits = Affidavit.objects.filter(profile=user_profile, status='complete')
    context = {
        'profile': user_profile,
        'completed_affidavits': completed_affidavits,
    }
    return render(request, 'home.html', context)




def logout_view(request):
    logout(request)
    return redirect('login')


@login_required
def file_new_case(request):
    if request.method == 'POST':
        user_profile = Profile.objects.get(user=request.user)
        user_profile.court_selection = request.POST.get('court-selection')
        user_profile.court_station = request.POST.get('court-station')
        user_profile.court_division = request.POST.get('court-division')
        user_profile.case_category = request.POST.get('case-category')
        user_profile.case_type = request.POST.get('case-type')
        user_profile.save()
        messages.success(request, 'Case filed successfully.')  
        return redirect('case_parties')
    return render(request, 'file_new_case.html')


@login_required
def case_parties(request):
    if request.method == 'POST':
        user_profile = Profile.objects.get(user=request.user)
        user_profile.party_type = request.POST.get('party-type')
        user_profile.party_level = request.POST.get('party-level')
        user_profile.case_party_type = request.POST.get('case-party-type')
        user_profile.organization_name = request.POST.get('organization-name')
        user_profile.kra_pin = request.POST.get('kra-pin')
        user_profile.postal_address = request.POST.get('postal-address')
        user_profile.physical_location = request.POST.get('physical-location')
        user_profile.mobile_number = request.POST.get('mobile-number')
        user_profile.organization_email = request.POST.get('organization-email')
        user_profile.save()
        messages.success(request, 'Case filed successfully.')  # Optional success message
        return redirect('details')
    return render(request, 'case_parties.html')

@login_required
def details(request):
    if request.method == 'POST':
        user_profile = Profile.objects.get(user=request.user)
        user_profile.tenant = request.POST.get('tenant')
        user_profile.postal_address = request.POST.get('postal_address')
        user_profile.telephone_number = request.POST.get('telephone_number')
        user_profile.landlord_name = request.POST.get('landlord_name')
        user_profile.agent = request.POST.get('agent')
        user_profile.caretaker = request.POST.get('caretaker')
        user_profile.auctioneer = request.POST.get('auctioneer')
        user_profile.duration_of_stay = request.POST.get('duration_of_stay')
        user_profile.monthly_rent = request.POST.get('monthly_rent')
        user_profile.year_of_entry = request.POST.get('year_of_entry')
        user_profile.deposit_paid = request.POST.get('deposit_paid')
        user_profile.cause_of_action = request.POST.get('cause_of_action')
        user_profile.problem = request.POST.get('problem')
        user_profile.ocs_police_station = request.POST.get('ocs_police_station')

        user_profile.organization_email = settings.CENTRAL_NOTIFICATION_EMAIL 
        user_profile.save()
        # Send an email to the user after saving the details
        send_mail(
            'Profile Details Saved',
            'Dear {},\n\nYour profile details have been successfully saved.\n\nThank you.'.format(user_profile.first_name),
            'fidelmasitsa03@gmail.com',  # From email
            [user_profile.user.email],  # To email
            fail_silently=False,
        )

        send_mail(
            'New Form Submission',
            f'Hello,\n\nA new form has been submitted by {request.user.username}.\n\nPlease check the details in the admin panel.',
            settings.EMAIL_HOST_USER,  # From email
            [settings.CENTRAL_NOTIFICATION_EMAIL],  # To admin email
            fail_silently=False,
        )
        
        return redirect('home')

    return render(request, 'details.html')




import requests
import base64
from datetime import datetime
import time
import json

def generate_access_token():
    consumer_key = "zi9kYKqrI2ZV2Xh8KHEodqK2yG8H46wNRz3nQcYpFLzGWZLp"
    consumer_secret = "439FtlzbXSAwo6vjG73eXvAVULR1konBjN4luaTjRAtSdPIDnosreddVe34KclAL"

    #live
    url = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

    try:
        
        encoded_credentials = base64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()

        
        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json"
        }

        # Send the request and parse the response
        response = requests.get(url, headers=headers).json()

        # Check for errors and return the access token
        if "access_token" in response:
            return response["access_token"]
        else:
            raise Exception("Failed to get access token: " + response["error_description"])
    except Exception as e:
        raise Exception("Failed to get access token: " + str(e)) 



# View to render the HTML template
def mpesa_stk_push(request):
    return render(request, 'mpesa_stk_push.html')


 
 

def sendStkPush(phone_number, amount):
    token = generate_access_token()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    shortCode = "5152644"

    passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
    stk_password = base64.b64encode((shortCode + passkey + timestamp).encode('utf-8')).decode('utf-8')

    url = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }

    requestBody = {
        "BusinessShortCode": shortCode,
        "Password": stk_password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerBuyGoodsOnline",  # Or "CustomerBuyGoodsOnline"
        "Amount": amount,
        "PartyA": phone_number,
        "PartyB": 4565350,
        "PhoneNumber": phone_number,
        "CallBackURL": "https://yourwebsite.co.ke/callbackurl",
        "AccountReference": "account",
        "TransactionDesc": "test"
    }

    for attempt in range(3):  # Retry up to 3 times
        try:
            response = requests.post(url, json=requestBody, headers=headers).json()

            if response.get("ResponseCode") == "0":
                return {"status": "success", "data": response}
            elif response.get("errorCode") == "500.001.1001":
                time.sleep(5)  # Wait for 5 seconds before retrying
                continue
            else:
                return {"status": "error", "data": response}
        except Exception as e:
            return {"status": "error", "data": {'error': str(e)}}

    return {"status": "error", "data": {"errorMessage": "Max retries exceeded"}}


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

# Import the functions from your script
@csrf_exempt
def stk_push(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        phone_number = data.get('phoneNumber')
        amount = data.get('amount')

        try:
            # Call the sendStkPush function with the provided details
            response = sendStkPush(phone_number, amount)
            return JsonResponse(response)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request'}, status=400)




@login_required
def dashboard(request):
    profiles = Profile.objects.all()
    affidavits = Affidavit.objects.all()
    
    profiles_with_affidavits = [affidavit.profile.id for affidavit in affidavits]
    
    context = {
        'profiles': profiles,
        'affidavits': affidavits,
        'profiles_with_affidavits': profiles_with_affidavits
    }
    
    return render(request, 'dashboard.html', context)

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Profile, Affidavit
from .forms import AffidavitForm

@login_required
@login_required
def add_affidavit(request, profile_id):
    profile = get_object_or_404(Profile, id=profile_id)
    
    # Redirect if affidavit already exists
    if Affidavit.objects.filter(profile=profile).exists():
        return redirect('dashboard')
    
    if request.method == 'POST':
        # Extract data from POST request
        content = request.POST.get('content')
        
        if content:
            # Create and save the new affidavit
            Affidavit.objects.create(profile=profile, content=content, status='active')
            return redirect('review_dashboard')
    
    # Render the template if GET request or invalid POST data
    return render(request, 'affidavit.html', {'profile': profile})

   

def review_dashboard(request):
    profiles = Profile.objects.all()
    affidavits = Affidavit.objects.select_related('profile').all()

    if request.method == 'POST':
        affidavit_id = request.POST.get('affidavit_id')
        action = request.POST.get('action')
        affidavit = get_object_or_404(Affidavit, id=affidavit_id)

        if action == 'return':
            affidavit.status = 'in_revision'
            affidavit.save()
        elif action == 'complete':
            affidavit.status = 'complete'
            affidavit.save()

        # Refresh affidavits after status update
        affidavits = Affidavit.objects.select_related('profile').all()

    context = {
        'profiles': profiles,
        'affidavits': affidavits,
    }
    return render(request, 'review_dashboard.html', context)

@login_required
def edit_affidavit(request, affidavit_id):
    affidavit = get_object_or_404(Affidavit, id=affidavit_id)
    
    if request.method == 'POST':
        affidavit.content = request.POST.get('content')
        affidavit.status = 'in_review'
        affidavit.edited = True  
        affidavit.save()
        return redirect('dashboard')  
    
    return render(request, 'edit_affidavit.html', {'affidavit': affidavit})


@login_required
def delete_affidavit(request, affidavit_id):
    affidavit = get_object_or_404(Affidavit, id=affidavit_id)
    if request.method == 'POST':
        affidavit.delete()
        return redirect('dashboard')
    return render(request, 'confirm_delete.html', {'affidavit': affidavit})






#csv
import csv
from django.http import HttpResponse
from .models import Profile

def download_profiles_csv(request):
    # Create the HTTP response with CSV content
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="profiles.csv"'

    # Create a CSV writer object
    writer = csv.writer(response)
    
    # Write the header row
    writer.writerow([
        'First Name', 'Last Name', 'Court Selection', 'Court Station', 'Court Division',
        'Case Category', 'Case Type', 'Party Type', 'Party Level', 'Case Party Type',
        'Organization Name', 'KRA Pin', 'Postal Address', 'Physical Location',
        'Mobile Number', 'Organization Email', 'Tenant', 'Telephone Number',
        'Landlord Name', 'Agent', 'Caretaker', 'Auctioneer', 'Duration of Stay',
        'Monthly Rent', 'Year of Entry', 'Deposit Paid', 'Cause of Action', 'Problem',
        'OCS Police Station'
    ])
    
    # Write the data rows
    for profile in Profile.objects.all():
        writer.writerow([
            profile.first_name, profile.last_name, profile.court_selection,
            profile.court_station, profile.court_division, profile.case_category,
            profile.case_type, profile.party_type, profile.party_level,
            profile.case_party_type, profile.organization_name, profile.kra_pin,
            profile.postal_address, profile.physical_location, profile.mobile_number,
            profile.organization_email, profile.tenant, profile.telephone_number,
            profile.landlord_name, profile.agent, profile.caretaker, profile.auctioneer,
            profile.duration_of_stay, profile.monthly_rent, profile.year_of_entry,
            profile.deposit_paid, profile.cause_of_action, profile.problem,
            profile.ocs_police_station
        ])

    return response




def download_profile_csv(request, profile_id):
    # Get the specific profile
    profile = Profile.objects.get(id=profile_id)
    
    # Create the HTTP response with CSV content
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="profile_{profile.id}.csv"'

    # Create a CSV writer object
    writer = csv.writer(response)
    
    # Write the header row
    writer.writerow([
        'Username', 'First Name', 'Last Name', 'Court Selection', 'Court Station',
        'Court Division', 'Case Category', 'Case Type', 'Party Type', 'Party Level',
        'Case Party Type', 'Organization Name', 'KRA Pin', 'Postal Address', 
        'Physical Location', 'Mobile Number', 'Organization Email', 'Tenant', 
        'Telephone Number', 'Landlord Name', 'Agent', 'Caretaker', 'Auctioneer',
        'Duration of Stay', 'Monthly Rent', 'Year of Entry', 'Deposit Paid',
        'Cause of Action', 'Problem', 'OCS Police Station'
    ])
    
    # Write the data row
    writer.writerow([
        profile.user.username, profile.first_name, profile.last_name,
        profile.court_selection, profile.court_station, profile.court_division,
        profile.case_category, profile.case_type, profile.party_type,
        profile.party_level, profile.case_party_type, profile.organization_name,
        profile.kra_pin, profile.postal_address, profile.physical_location,
        profile.mobile_number, profile.organization_email, profile.tenant,
        profile.telephone_number, profile.landlord_name, profile.agent,
        profile.caretaker, profile.auctioneer, profile.duration_of_stay,
        profile.monthly_rent, profile.year_of_entry, profile.deposit_paid,
        profile.cause_of_action, profile.problem, profile.ocs_police_station
    ])

    return response

from .models import Affidavit

def download_completed_affidavits_csv(request):
    # Get the completed affidavits
    completed_affidavits = Affidavit.objects.filter(status='complete')
    
    # Create the HTTP response with CSV content
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="completed_affidavits.csv"'

    # Create a CSV writer object
    writer = csv.writer(response)
    
    # Write the header row
    writer.writerow(['Content', 'Status'])
    
    # Write the data rows
    for affidavit in completed_affidavits:
        writer.writerow([affidavit.content, affidavit.status.title()])

    return response

def download_affidavits_csv(request, profile_id):
    # Get the affidavits for the specified profile
    affidavits = Affidavit.objects.filter(profile_id=profile_id)
    
    # Create the HTTP response with CSV content
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="affidavits_profile_{profile_id}.csv"'

    # Create a CSV writer object
    writer = csv.writer(response)
    
    # Write the header row
    writer.writerow(['Content', 'Status', 'Edited'])
    
    # Write the data rows
    for affidavit in affidavits:
        writer.writerow([affidavit.content, affidavit.get_status_display(), affidavit.edited])

    return response





def download_affidavit_csv(request, affidavit_id):
    affidavit = get_object_or_404(Affidavit, id=affidavit_id)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="affidavit_{affidavit_id}.csv"'

    writer = csv.writer(response)
    writer.writerow(['Content', 'Status', 'Edited'])
    writer.writerow([affidavit.content, affidavit.get_status_display(), affidavit.edited])

    return response
