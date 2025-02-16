from django.apps import AppConfig


class createConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'create'

    def ready(self):
        import create.signals
