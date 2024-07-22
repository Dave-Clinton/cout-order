from django import forms
from .models import Affidavit

class AffidavitForm(forms.ModelForm):
    class Meta:
        model = Affidavit
        fields = ['content']


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Affidavit
        fields = ['status']


