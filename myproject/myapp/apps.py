from django.apps import AppConfig


class MyappConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'



from django.apps import AppConfig

class UsersConfig(AppConfig):
    name = 'myapp'

    def ready(self):
        import myapp.signals
