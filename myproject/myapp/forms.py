from django import forms
from .models import Affidavit
from ckeditor.widgets import CKEditorWidget

class AffidavitForm(forms.ModelForm):
    content = forms.CharField(widget=CKEditorWidget())

    class Meta:
        model = Affidavit
        fields = ['content']


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Affidavit
        fields = ['status']


