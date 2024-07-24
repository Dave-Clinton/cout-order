from django.contrib.auth.models import User
from django.db import models
import uuid

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email_verified = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    verification_code = models.UUIDField(default=uuid.uuid4, editable=False)
    is_verified = models.BooleanField(default=False)
    court_selection = models.CharField(max_length=50, blank=True, null=True)
    court_station = models.CharField(max_length=50, blank=True, null=True)
    court_division = models.CharField(max_length=50, blank=True, null=True)
    case_category = models.CharField(max_length=50, blank=True, null=True)
    case_type = models.CharField(max_length=50, blank=True, null=True)
    party_type = models.CharField(max_length=50, blank=True, null=True)
    party_level = models.CharField(max_length=100, blank=True, null=True)
    case_party_type = models.CharField(max_length=100, blank=True, null=True)
    organization_name = models.CharField(max_length=100, blank=True, null=True)
    kra_pin = models.CharField(max_length=100, blank=True, null=True)
    postal_address = models.CharField(max_length=100, blank=True, null=True)
    physical_location = models.CharField(max_length=100, blank=True, null=True)
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    organization_email = models.EmailField(blank=True, null=True)
    tenant = models.CharField(max_length=100, blank=True, null=True)
    telephone_number = models.CharField(max_length=15, blank=True, null=True)
    landlord_name = models.CharField(max_length=100, blank=True, null=True)
    agent = models.CharField(max_length=100, blank=True, null=True)
    caretaker = models.CharField(max_length=100, blank=True, null=True)
    auctioneer = models.CharField(max_length=100, blank=True, null=True)
    duration_of_stay = models.CharField(max_length=50, blank=True, null=True)
    monthly_rent = models.CharField(max_length=20, blank=True, null=True)
    year_of_entry = models.CharField(max_length=20, blank=True, null=True)
    deposit_paid = models.CharField(max_length=20, blank=True, null=True)
    cause_of_action = models.CharField(max_length=255, blank=True, null=True)
    problem = models.TextField(blank=True, null=True)
    ocs_police_station = models.CharField(max_length=100, blank=True, null=True)
    def __str__(self):
        return f'{self.user.username} Profile'

class Affidavit(models.Model):
    profile = models.OneToOneField(Profile, on_delete=models.CASCADE)
    content = models.TextField()
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('in_review', 'In Review'),
        ('in_revision', 'In Revision'),
        ('complete', 'Complete'),
    ]
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    edited = models.BooleanField(default=False)  # New field to track if the affidavit has been edited

    def __str__(self):
        return f'Affidavit for {self.profile.user.username}'

